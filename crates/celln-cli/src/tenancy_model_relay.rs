//! Linux host gateway transport. No provider credentials, credential files,
//! guest-selected destination, redirects, ambient proxies or transport retries.
use crate::tenancy_model_context::{canonical_model_request, ModelContext};
use serde_json::Value;
use std::{path::PathBuf, process::Command};
use warden::egress::{FetchDenied, ModelRelay};
use zeroize::Zeroizing;

fn refused() -> FetchDenied {
    FetchDenied::Fetch("mediated model invocation unavailable or uncertain".into())
}

/// Operator-owned configuration, never derived from a tenant decision or guest.
/// The CA path contains public trust material only; system roots are the default.
pub struct GatewayEndpoint {
    url: String,
    ca: Option<PathBuf>,
}
impl GatewayEndpoint {
    pub fn new(origin: &str, ca: Option<PathBuf>) -> Result<Self, FetchDenied> {
        let url = url::Url::parse(origin).map_err(|_| refused())?;
        if origin.bytes().any(|b| b.is_ascii_whitespace())
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(refused());
        }
        Ok(Self {
            url: url.join("v1/invoke").map_err(|_| refused())?.to_string(),
            ca,
        })
    }
}

/// Owned once by an admitted operation. There is deliberately no Clone,
/// serialization or restore API. Owner recovery must find this original context
/// or report ContextLost; constructing a fresh context is not replay recovery.
pub struct GatewayRelay {
    endpoint: GatewayEndpoint,
    context: ModelContext,
    sequence: u64,
    scope: String,
}
impl GatewayRelay {
    pub fn new(endpoint: GatewayEndpoint, context: ModelContext) -> Self {
        let scope = crate::tenancy_contract::digest(&context.decision);
        Self {
            endpoint,
            context,
            sequence: 0,
            scope,
        }
    }
}

// curl config quoting is NOT JSON quoting. Escape backslashes before all other
// syntax, so JSON escapes cannot become curl config directives or new headers.
fn quote(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

impl ModelRelay for GatewayRelay {
    fn invoke(&mut self, raw: &[u8]) -> Result<Vec<u8>, FetchDenied> {
        let (body, _) = canonical_model_request(raw).map_err(|_| refused())?;
        let request: Value = serde_json::from_slice(&body).map_err(|_| refused())?;
        if !request.is_object() {
            return Err(refused());
        }
        let decision: Value =
            serde_json::from_slice(&self.context.decision).map_err(|_| refused())?;
        self.sequence = self.sequence.checked_add(1).ok_or_else(refused)?;
        let envelope = serde_json::json!({
            "decision": decision,
            "requestId": format!("celln:{}:{}", self.scope, self.sequence),
            "request": request,
        })
        .to_string();
        // Advance before transport; a lost response is never silently retried.
        let endpoint = &self.endpoint;
        self.context
            .with_bearer(|bearer, control| {
                if !bearer
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                {
                    return Err(refused());
                }
                let config = Zeroizing::new(format!(
                    "header = \"Authorization: Bearer {}\"\ndata-binary = \"{}\"\n",
                    bearer,
                    quote(&envelope),
                ));
                let mut command = Command::new("/usr/bin/curl");
                command.env_clear().args([
                    "--disable",
                    "--silent",
                    "--show-error",
                    "--globoff",
                    "--noproxy",
                    "*",
                    "--proto",
                    "=https",
                    "--max-redirs",
                    "0",
                    "--retry",
                    "0",
                    "--request",
                    "POST",
                    "--header",
                    "Content-Type: application/json",
                    "--max-filesize",
                    "1048576",
                    "--config",
                    "-",
                    "--write-out",
                    "\n%{http_code}\n%{content_type}",
                    "--url",
                    &endpoint.url,
                ]);
                if let Some(ca) = &endpoint.ca {
                    command.arg("--cacert").arg(ca);
                }
                let output = control
                    .scope(|| {
                        celln_control::process::output_with_input(
                            &mut command,
                            config.as_bytes(),
                            control.remaining(),
                        )
                    })
                    .map_err(|_| refused())?;
                // Never relay subprocess diagnostics; they may contain remote data.
                let _stderr = Zeroizing::new(output.stderr);
                let stdout = Zeroizing::new(output.stdout);
                if !output.status.success() {
                    return Err(refused());
                }
                let text = std::str::from_utf8(&stdout).map_err(|_| refused())?;
                let mut parts = text.rsplitn(3, '\n');
                if parts.next() != Some("application/json") {
                    return Err(refused());
                }
                let status = parts.next().ok_or_else(refused)?;
                let response = parts.next().ok_or_else(refused)?;
                if status == "429" {
                    return Err(FetchDenied::Budget);
                }
                if status != "200" || response.len() > 1048576 {
                    return Err(refused());
                }
                validate_response(response, bearer)?;
                let value: Value = serde_json::from_str(response).map_err(|_| refused())?;
                if !value.is_object() {
                    return Err(refused());
                }
                Ok(response.as_bytes().to_vec())
            })
            .map_err(|_| refused())?
    }
}

// Visit every decoded string BEFORE normalizing into a map: a duplicate key
// must not hide a credential echo in an overwritten value. Provider floats are
// permitted here; integer-only canonicalization applies to requests, not output.
fn validate_response(raw: &str, bearer: &str) -> Result<(), FetchDenied> {
    use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
    #[derive(Clone, Copy)]
    struct Scan<'a>(&'a str);
    impl<'de> DeserializeSeed<'de> for Scan<'_> {
        type Value = ();
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Scan<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("safe JSON response")
        }
        fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
            Ok(())
        }
        fn visit_unit<E: de::Error>(self) -> Result<(), E> {
            Ok(())
        }
        fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
            Ok(())
        }
        fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
            Ok(())
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
            Ok(())
        }
        fn visit_str<E: de::Error>(self, s: &str) -> Result<(), E> {
            if s.contains(self.0) {
                Err(E::custom("unsafe response"))
            } else {
                Ok(())
            }
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
            while a.next_element_seed(self)?.is_some() {}
            Ok(())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
            let mut keys = std::collections::BTreeSet::new();
            while let Some(k) = a.next_key::<String>()? {
                if k.contains(self.0) || !keys.insert(k) {
                    return Err(de::Error::custom("unsafe response"));
                }
                a.next_value_seed(self)?;
            }
            Ok(())
        }
    }
    let mut decoder = serde_json::Deserializer::from_str(raw);
    Scan(bearer)
        .deserialize(&mut decoder)
        .map_err(|_| refused())?;
    decoder.end().map_err(|_| refused())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gateway_origin_cannot_supply_credentials_or_transport_overrides() {
        for origin in [
            "http://localhost",
            "https://u:p@host",
            "https://host/path",
            "https://host/?x",
            "https://host/#x",
            " https://host",
        ] {
            assert!(GatewayEndpoint::new(origin, None).is_err(), "{origin}");
        }
        let endpoint = GatewayEndpoint::new("https://gateway.example:8443", None).unwrap();
        assert_eq!(endpoint.url, "https://gateway.example:8443/v1/invoke");
    }
    #[test]
    fn config_quoting_cannot_inject_directives() {
        assert_eq!(
            quote("a\\b\"\nheader = x\r\t"),
            "a\\\\b\\\"\\nheader = x\\r\\t"
        );
        assert!(validate_response(r#"{"nested":["prefix-secret-suffix"]}"#, "secret").is_err());
        assert!(validate_response(r#"{"x":"secr\u0065t","x":"safe"}"#, "secret").is_err());
        assert!(validate_response(r#"{"x":1,"x":2}"#, "secret").is_err());
        assert!(validate_response(r#"{"logprob":0.5}"#, "secret").is_ok());
    }
}
