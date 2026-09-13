//! Host-only, per-operation model capability custody. No provider keys, token
//! files, serialization or guest-facing types. Broker wiring remains separate.
use crate::tenancy_credentials::{Context, Refusal, Verifier};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use celln_control::Control;
use serde_json::Value;
use std::{fmt, time::Duration};
use zeroize::Zeroizing;

/// Canonical provider body and typed digest for the v1 gateway reservation
/// protocol. Uses the independently implemented integer-only JCS encoder;
/// neither Go/serde map ordering nor ordinary JSON escaping is a wire contract.
/// No network operation, allowance reservation or retry is performed here.
pub fn canonical_model_request(raw: &[u8]) -> Result<(Vec<u8>, String), Refusal> {
    let body = crate::tenancy_contract::canonical(raw).map_err(|_| "AUTH_PROTOCOL_UNSUPPORTED")?;
    fn depth(value: &Value) -> usize {
        match value {
            Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
            Value::Object(items) => 1 + items.values().map(depth).max().unwrap_or(0),
            _ => 0,
        }
    }
    let value: Value = serde_json::from_slice(&body).map_err(|_| "AUTH_PROTOCOL_UNSUPPORTED")?;
    if depth(&value) > 64 {
        return Err("AUTH_PROTOCOL_UNSUPPORTED");
    }
    let digest = crate::tenancy_contract::digest(&body);
    Ok((body, digest))
}

pub struct ModelContext {
    pub(crate) decision: Vec<u8>,
    bearer: Option<Zeroizing<String>>,
    control: Control,
}
impl fmt::Debug for ModelContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ModelContext([REDACTED])")
    }
}
impl ModelContext {
    /// The caller supplies trusted receiver identity and its original monotonic
    /// parent/run control. Both credentials must bind the SAME decision bytes.
    /// This does not independently authorize a host artifact or parent launch.
    pub fn admit(
        verifier: &Verifier,
        execution_token: String,
        model_token: String,
        decision: &[u8],
        receiver: &Context,
        parent: &Control,
    ) -> Result<Self, Refusal> {
        let execution_token = Zeroizing::new(execution_token);
        let model_token = Zeroizing::new(model_token);
        if !matches!(
            receiver.expected_operation.as_str(),
            "execution.start" | "execution.turn"
        ) {
            return Err("AUTH_OPERATION_MISMATCH");
        }
        if verifier
            .verify(&execution_token, decision, receiver)?
            .is_some()
        {
            // Recovery must locate the existing owner/context, not silently
            // reconstruct forgotten bearer custody from a replayed permit.
            return Err("AUTH_CONTEXT_LOST");
        }
        let mut model_receiver = receiver.clone();
        model_receiver.expected_operation = "model.invoke".into();
        model_receiver.expected_audience = "sympozium-model-gateway".into();
        verifier.verify(&model_token, decision, &model_receiver)?;
        // Read expiration only AFTER signature and full decision verification.
        let payload = model_token.split('.').nth(1).ok_or("AUTH_CRED_MALFORMED")?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "AUTH_CRED_MALFORMED")?;
        let claims: Value = serde_json::from_slice(&payload).map_err(|_| "AUTH_CRED_MALFORMED")?;
        let d: Value = serde_json::from_slice(decision).map_err(|_| "AUTH_CRED_MALFORMED")?;
        let expiry = claims["exp"].as_i64().ok_or("AUTH_CRED_MALFORMED")?;
        let work = d["budget"]["turnDeadlineUnix"]
            .as_i64()
            .ok_or("AUTH_CRED_MALFORMED")?;
        let remaining = (expiry.min(work) as i128) - (receiver.now as i128);
        if remaining <= 0 || remaining > u64::MAX as i128 {
            return Err("AUTH_WORK_DEADLINE_EXPIRED");
        }
        let control = parent
            .child(Duration::from_secs(remaining as u64))
            .map_err(|_| "AUTH_WINDOW_INVALID")?;
        control.check().map_err(|_| "AUTH_WORK_DEADLINE_EXPIRED")?;
        Ok(Self {
            decision: crate::tenancy_contract::canonical(decision)
                .map_err(|_| "AUTH_CRED_MALFORMED")?,
            bearer: Some(model_token),
            control,
        })
    }

    /// Narrow host broker hook. The credential is never returned as an owned
    /// value by this API. Host code must inject only at its configured gateway
    /// origin and must not put this borrow into guest input or a durable record.
    pub fn with_bearer<T>(&mut self, send: impl FnOnce(&str, &Control) -> T) -> Result<T, Refusal> {
        if self.control.check().is_err() {
            self.bearer.take();
            return Err("AUTH_WORK_DEADLINE_EXPIRED");
        }
        let bearer = self.bearer.as_ref().ok_or("AUTH_CONTEXT_LOST")?;
        Ok(send(bearer, &self.control))
    }
    /// Owner stop drops the token immediately and cooperatively cancels broker
    /// work. This does not assert native parent teardown or undo provider spend.
    pub fn close(&mut self) {
        self.control.cancel();
        self.bearer.take();
    }
}
#[cfg(test)]
#[path = "tenancy_model_context_tests.rs"]
mod tests;

impl Drop for ModelContext {
    fn drop(&mut self) {
        self.close();
    }
}
