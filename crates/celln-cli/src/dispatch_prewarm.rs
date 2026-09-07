//! Authenticated serving-process member verification and warm-cache observation.
use super::*;

#[cfg(test)]
#[path = "dispatch_prewarm_tests.rs"]
mod tests;
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn prove_prewarm_on_kvm(request: &ExecutionRequest, root: &Path, source: &str) {
    tests::prove_prewarm_on_kvm(request, root, source);
}

struct Lease<'a>(&'a State);
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        *self
            .0
            .prewarm
            .lock()
            .expect("prewarm reservation not poisoned") = None;
    }
}

pub(super) fn handle(
    state: &State,
    stream: &mut TcpStream,
    reader: &mut impl Read,
    length: usize,
) -> Result<()> {
    if length > 65536 {
        return reply(
            stream,
            413,
            &serde_json::json!({"error":"prewarm request exceeds 64 KiB"}),
        );
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    let request: ExecutionRequest = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(_) => {
            return reply(
                stream,
                400,
                &serde_json::json!({"error":"invalid prewarm request"}),
            )
        }
    };
    if let Err(reason) = crate::dispatch::validate_member_request(&request) {
        return reply(stream, 422, &serde_json::json!({"error":reason}));
    }
    // Same lock/order as execution admission: a member-check cell cannot
    // overcommit an execution admitted concurrently. Only one preparation is
    // retained/in progress here; no unbounded result or retry-ID registry.
    let registry = state
        .executions
        .lock()
        .expect("dispatcher registry not poisoned");
    if state
        .prewarm
        .lock()
        .expect("prewarm reservation not poisoned")
        .is_some()
    {
        return reply(
            stream,
            503,
            &serde_json::json!({"error":"prewarm already in progress"}),
        );
    }
    let node = current_node(state, &registry);
    if let crate::node::Admission::Refused { reason, .. } = crate::node::admit(&request, &node) {
        let status = if reason == crate::node::RefusalCode::AtCapacity {
            503
        } else {
            422
        };
        return reply(
            stream,
            status,
            &serde_json::json!({"error":"prewarm admission refused","reason":reason}),
        );
    }
    *state
        .prewarm
        .lock()
        .expect("prewarm reservation not poisoned") = Some(Reservation::for_request(&request));
    let _lease = Lease(state);
    drop(registry);
    let control = celln_control::Control::new(Duration::from_millis(
        request.capabilities.timeout_ms.min(30000),
    ))?;
    let report = control.scope(|| {
        crate::dispatch::check_members(
            &request,
            &state.probe.mote_store,
            &state.probe.tool_store,
            &state.root,
        )
    });
    let report = match report {
        Ok(report) => report,
        Err(reason) => {
            return reply(
                stream,
                422,
                &serde_json::json!({"error":"sealed prewarm verification refused","reason":reason}),
            )
        }
    };
    #[cfg(target_os = "linux")]
    let warm = crate::dispatch::warm::availability().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry.mote.as_deref() == request.mote.as_ref().map(|m| m.hash.as_str())
                && entry.guest_memory_bytes == request.capabilities.memory_bytes
        })
    });
    #[cfg(not(target_os = "linux"))]
    let warm = false;
    if !warm {
        return reply(
            stream,
            503,
            &serde_json::json!({"error":"verified template no longer observable in serving cache"}),
        );
    }
    // An opaque process-incarnation observation, not an authentication token.
    static EPOCH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let epoch = EPOCH.get_or_init(|| {
        celln_manifest::Hash::of(
            format!("{}:{:?}", std::process::id(), std::time::SystemTime::now()).as_bytes(),
        )
        .0
    });
    reply(
        stream,
        200,
        &serde_json::json!({"apiVersion":"celln.dev/artifact-prewarm-v1","node":state.probe.node_name,
        "processEpoch":epoch,"requestHash":celln_manifest::Hash::of(&bytes).0,"verification":report,
        "warmState":"present-at-observation","validity":"observation-only","executionAuthorized":false,
        "conformance":"not_checked","artifactReadiness":"not_checked"}),
    )
}
