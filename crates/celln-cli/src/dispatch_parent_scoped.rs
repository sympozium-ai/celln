//! Native parent/worker composition using original, scoped per-turn broker
//! custody. The receiver must first independently admit the operation and derive
//! the local native permit; this module is not an HTTP authorisation shortcut.
use super::*;

pub(crate) type Brokers = parent_worker::ScopedTurnBrokers;

pub(crate) struct Plan {
    pub parent: ExecutionRequest,
    pub worker: ExecutionRequest,
    pub template: pilot::json_harness::Config,
    pub permit: Hash,
    pub binding: warden::parent_permit::Binding,
}

pub(crate) fn worker_binding(
    request: &ExecutionRequest,
    config: &pilot::json_harness::Config,
) -> Result<Hash, String> {
    let template = pilot::turn_worker::Template::new(config.clone()).map_err(|e| e.to_string())?;
    parent_worker::scoped_worker_binding(request, &template)
}

/// Burn the native incarnation before any warm preparation, then transfer the
/// unique factory to the retained owner thread. The enclosing registry must
/// reserve capacity and install an original-deadline Control; teardown remains
/// its responsibility. No standing model profile/credential file is consulted.
pub(crate) fn claim(
    root: PathBuf,
    plan: Plan,
    principal: &str,
    brokers: Brokers,
) -> Result<
    impl FnOnce(
            std::sync::Arc<warden::parent_child_control::ChildControlSlot>,
        ) -> Result<Handler, String>
        + Send,
    String,
> {
    validate_parent_request(&plan.parent, &plan.binding)?;
    let template = pilot::turn_worker::Template::new(plan.template).map_err(|e| e.to_string())?;
    if parent_worker::scoped_worker_binding(&plan.worker, &template)?
        != plan.binding.worker_configuration
        || plan.worker.workload.caller != principal
        || plan.binding.principal != principal
    {
        return Err("scoped worker is not bound to the native parent permit".into());
    }
    let claim = warden::parent_permit::claim(&root, &plan.permit, &plan.binding, principal)
        .map_err(|e| e.to_string())?;
    Ok(move |children| {
        celln_control::current()
            .ok_or("scoped parent requires its original live control")?
            .check()
            .map_err(|e| e.to_string())?;
        let motes = root.join("motes");
        let tools = root.join("tools");
        let parent = prepare_parent(
            &plan.parent,
            &motes,
            &tools,
            &root,
            &plan.permit,
            &plan.binding,
            &plan.binding.principal,
        )?;
        let worker = parent_worker::prepare_worker_scoped(
            &plan.worker,
            template,
            &plan.binding,
            &motes,
            &tools,
            &root,
            brokers,
        )?;
        let mut session = parent.into_claimed_session(worker, Some(claim), Some(children))?;
        Ok(
            Box::new(move |bytes: &[u8]| session.submit(bytes).map_err(|e| e.to_string()))
                as Handler,
        )
    })
}
