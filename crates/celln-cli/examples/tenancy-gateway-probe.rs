//! Integration-test driver, NOT a production admission API. All input comes
//! from the trusted Go fixture over stdin. In production the receiver context
//! must instead come from independently admitted, durable owner state.
#[cfg(target_os = "linux")]
fn run() -> Result<(), ()> {
    use celln_cli::{
        tenancy_credentials::{Context, Verifier},
        tenancy_model_context::ModelContext,
        tenancy_model_relay::{GatewayEndpoint, GatewayRelay},
    };
    use serde::Deserialize;
    use serde_json::Value;
    use std::{io::Read, time::Duration};
    use warden::egress::{HttpBroker, HttpPolicy, JsonPostGrant};
    use zeroize::Zeroizing;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Input {
        jwks: Value,
        receiver: Context,
        execution_token: String,
        model_token: String,
        decision: Value,
        gateway_origin: String,
        gateway_ca: std::path::PathBuf,
        requests: Vec<Value>,
        #[serde(default = "default_timeout")]
        timeout_ms: u64,
    }
    fn default_timeout() -> u64 {
        15000
    }
    let mut raw = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(1048577)
        .read_to_end(&mut raw)
        .map_err(|_| ())?;
    if raw.len() > 1048576 {
        return Err(());
    }
    let input: Input = serde_json::from_slice(&raw).map_err(|_| ())?;
    let verifier = Verifier::from_jwks(
        "sympozium-control-plane".into(),
        &serde_json::to_vec(&input.jwks).map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let root = celln_control::Control::new(Duration::from_millis(input.timeout_ms.min(15000)))
        .map_err(|_| ())?;
    let context = ModelContext::admit(
        &verifier,
        input.execution_token,
        input.model_token,
        &serde_json::to_vec(&input.decision).map_err(|_| ())?,
        &input.receiver,
        &root,
    )
    .map_err(|_| ())?;
    let relay = GatewayRelay::new(
        GatewayEndpoint::new(&input.gateway_origin, Some(input.gateway_ca)).map_err(|_| ())?,
        context,
    );
    let mut policy = HttpPolicy::new(vec![]);
    policy.max_requests = 8; // Deliberately above gateway fixture cap: prove durable refusal, not just local count.
    policy.max_response_bytes = 1048576;
    policy.json_posts.push(JsonPostGrant {
        protocol: Default::default(),
        url: "https://model.invalid/invoke".into(),
        bearer_token_file: Default::default(),
        model: input.decision["route"]["model"].as_str().ok_or(())?.into(),
        max_output_tokens: 512,
        max_total_output_tokens: 4096,
    });
    let mut broker = HttpBroker::new_mediated(policy, Box::new(relay)).map_err(|_| ())?;
    let results: Vec<Value> = input.requests.into_iter().map(|body| {
        let wire = serde_json::json!({"apiVersion":"celln.fetch/v1","method":"POST","url":"https://model.invalid/invoke","body":body}).to_string();
        match broker.fetch(&wire) {
            Ok(body) => serde_json::json!({"ok":true,"body":serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null)}),
            Err(warden::egress::FetchDenied::Budget) => serde_json::json!({"ok":false,"budget":true}),
            Err(_) => serde_json::json!({"ok":false,"budget":false}),
        }
    }).collect();
    println!("{}", serde_json::to_string(&results).map_err(|_| ())?);
    Ok(())
}
fn main() {
    #[cfg(target_os = "linux")]
    if run().is_ok() {
        return;
    }
    eprintln!("gateway probe refused");
    std::process::exit(1);
}
