//! Parent affinity is published BEFORE create, including the immutable caller
//! incarnation. Lost responses and gateway restarts never authorize recreation.
use super::*;
use serde_json::json;

fn hash_valid(id: &str) -> bool {
    id.strip_prefix("blake3:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn parent_id<'a>(method: &str, path: &'a str) -> Option<&'a str> {
    let parts: Vec<_> = path.strip_prefix("/v1/parents/")?.split('/').collect();
    let id = *parts.first()?;
    if !hash_valid(id) {
        return None;
    }
    let valid = match (method, &parts[1..]) {
        ("GET", []) | ("POST", ["stop" | "cancel" | "turns"]) => true,
        ("GET", ["turns", turn]) | ("POST", ["turns", turn, "cancel"]) => {
            !turn.is_empty()
                && turn.len() <= 64
                && turn
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        }
        _ => false,
    };
    valid.then_some(id)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn forward(
    state: &RouterState,
    stream: &mut TcpStream,
    reader: &mut impl Read,
    method: &str,
    path: &str,
    length: usize,
    incarnation: Option<&str>,
    respond_async: bool,
    backend_token: &Option<String>,
) -> Result<()> {
    let token = match state
        .parent_token_file
        .as_deref()
        .map(read_token)
        .transpose()
    {
        Ok(Some(token)) => token,
        _ => {
            return reply(
                stream,
                503,
                &json!({"error":"parent routing is not configured"}),
            )
        }
    };
    // The capability bearer must never acquire a parent principal via reuse.
    let (client, backend, capability) = credentials(state)?;
    if [&client, &backend]
        .into_iter()
        .chain(capability.iter())
        .any(|other| constant_time_eq(token.as_bytes(), other.as_bytes()))
    {
        return reply(
            stream,
            503,
            &json!({"error":"parent credential must be distinct"}),
        );
    }
    let create = method == "POST" && path == "/v1/parents";
    let id = if create {
        incarnation.filter(|id| hash_valid(id))
    } else {
        parent_id(method, path)
    };
    let Some(id) = id else {
        return reply(
            stream,
            400,
            &json!({"error":"invalid parent route or missing immutable incarnation"}),
        );
    };
    if length > 65536 || (method == "GET" && length != 0) {
        return reply(stream, 400, &json!({"error":"invalid parent body length"}));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let backend = if create {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Create {
            api_version: String,
            launch_profile: String,
        }
        let parsed: Create = match serde_json::from_slice(&body) {
            Ok(value) => value,
            Err(_) => return reply(stream, 400, &json!({"error":"invalid parent create"})),
        };
        if parsed.api_version != "celln.parent-create/v1" || !hash_valid(&parsed.launch_profile) {
            return reply(stream, 400, &json!({"error":"invalid parent create"}));
        }
        match state
            .parents
            .claim(id, &body, || pick_backend(state, id, backend_token))
        {
            Ok(ownership::Claim::New(owner)) => owner.backend,
            Ok(ownership::Claim::Existing(_)) | Ok(ownership::Claim::Conflict) => {
                return reply(
                    stream,
                    409,
                    &json!({"error":"parent identity already claimed; reconcile original owner", "retryAuthorized":false}),
                );
            }
            _ => {
                return reply(
                    stream,
                    503,
                    &json!({"error":"parent ownership unavailable", "retryAuthorized":false}),
                )
            }
        }
    } else {
        match state.parents.lookup(id) {
            Ok(Some(owner)) => owner.backend,
            Ok(None) => {
                return reply(
                    stream,
                    404,
                    &json!({"error":"parent owner unknown", "retryAuthorized":false}),
                )
            }
            Err(_) => {
                return reply(
                    stream,
                    503,
                    &json!({"error":"parent ownership unavailable", "retryAuthorized":false}),
                )
            }
        }
    };
    if !state.backends.contains(&backend) {
        return reply(
            stream,
            503,
            &json!({"error":"original parent backend removed", "retryAuthorized":false}),
        );
    }
    // No health-based reselection, forwarding retry, or automatic POST replay.
    let response = (|| -> Result<String> {
        let mut conn = connect(&backend_to_addr(&backend)?)?;
        write!(conn, "{method} {path} HTTP/1.1\r\nHost: dispatcher\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n", body.len())?;
        if respond_async {
            write!(conn, "Prefer: respond-async\r\n")?;
        }
        write!(conn, "\r\n")?;
        conn.write_all(&body)?;
        conn.flush()?;
        read_response(&mut conn)
    })();
    match response {
        Ok(response) => {
            if create && (200..300).contains(&parse_status(&response)) {
                let result: serde_json::Value = serde_json::from_str(extract_body(&response))?;
                if result["incarnation"].as_str() != Some(id) {
                    return reply(
                        stream,
                        502,
                        &json!({"error":"parent owner returned another incarnation", "retryAuthorized":false}),
                    );
                }
            }
            raw_reply(stream, &response)
        }
        Err(_) => reply(
            stream,
            502,
            &json!({"error":"parent outcome uncertain; reconcile original owner", "retryAuthorized":false}),
        ),
    }
}
