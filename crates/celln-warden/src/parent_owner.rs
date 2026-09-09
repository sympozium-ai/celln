//! Bounded serving-thread owner for a persistent runtime. Its handler must own
//! all VM resources and use the scoped celln-control-aware KVM/broker paths.
//! This is not a force-kill mechanism for arbitrary uncooperative callbacks.
use celln_control::Control;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

type Reply = Result<Vec<u8>, String>;
struct Command {
    bytes: Vec<u8>,
    reply: mpsc::SyncSender<Reply>,
}

pub struct ParentOwner {
    sender: mpsc::SyncSender<Command>,
    control: Control,
    busy: Arc<AtomicBool>,
    initialized: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    children: Option<Arc<crate::parent_child_control::ChildControlSlot>>,
}

impl ParentOwner {
    /// Construct the runtime on its owning thread; VM state need not migrate
    /// between threads. Preparation and every exchange share one deadline.
    pub fn spawn<F, H>(lifetime: Duration, initialize: F) -> std::io::Result<Self>
    where
        F: FnOnce() -> Result<H, String> + Send + 'static,
        H: FnMut(&[u8]) -> Reply + 'static,
    {
        let control = Control::new(lifetime)?;
        Self::spawn_controlled(control, initialize, None)
    }

    /// Share one child rendezvous between the owning runtime and authenticated
    /// routing. It inherits this owner's control; no independently extended lease.
    pub fn spawn_with_children<F, H>(
        parent: celln_manifest::Hash,
        lifetime: Duration,
        initialize: F,
    ) -> std::io::Result<Self>
    where
        F: FnOnce(Arc<crate::parent_child_control::ChildControlSlot>) -> Result<H, String>
            + Send
            + 'static,
        H: FnMut(&[u8]) -> Reply + 'static,
    {
        let control = Control::new(lifetime)?;
        let children = Arc::new(crate::parent_child_control::ChildControlSlot::new(
            parent,
            control.clone(),
        ));
        let runtime_children = children.clone();
        Self::spawn_controlled(
            control,
            move || initialize(runtime_children),
            Some(children),
        )
    }

    fn spawn_controlled<F, H>(
        control: Control,
        initialize: F,
        children: Option<Arc<crate::parent_child_control::ChildControlSlot>>,
    ) -> std::io::Result<Self>
    where
        F: FnOnce() -> Result<H, String> + Send + 'static,
        H: FnMut(&[u8]) -> Reply + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel::<Command>(1);
        let busy = Arc::new(AtomicBool::new(false));
        let initialized = Arc::new(AtomicBool::new(false));
        let owner_initialized = initialized.clone();
        let owner_control = control.clone();
        let owner_busy = busy.clone();
        let thread = thread::Builder::new()
            .name("celln-parent-owner".into())
            .spawn(move || {
                owner_control.scope(|| {
                    if owner_control.check().is_err() {
                        return;
                    }
                    let Ok(mut runtime) = initialize() else {
                        owner_control.cancel();
                        return;
                    };
                    // The admitted constructor returns only after the native
                    // parent's protected execution acknowledgement. Publish
                    // startup completion separately from queue availability.
                    owner_initialized.store(true, Ordering::Release);
                    loop {
                        if owner_control.check().is_err() {
                            break;
                        }
                        let command = match receiver
                            .recv_timeout(Duration::from_millis(20).min(owner_control.remaining()))
                        {
                            Ok(command) => command,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        };
                        let result = owner_control
                            .check()
                            .map_err(|e| e.to_string())
                            .and_then(|_| runtime(&command.bytes))
                            .and_then(|output| {
                                owner_control.check().map_err(|e| e.to_string())?;
                                if output.len() > crate::parent_mailbox::MAX_FRAME_BYTES {
                                    Err("parent response exceeds owner bound".into())
                                } else {
                                    Ok(output)
                                }
                            });
                        let failed = result.is_err();
                        if failed {
                            owner_control.cancel();
                        }
                        // Publish readiness before acknowledgement: once the
                        // client observes completion it may submit the next turn.
                        // Failed handlers already cancelled admission above.
                        owner_busy.store(false, Ordering::Release);
                        let _ = command.reply.send(result);
                        // A handler failure can mean lost live context. Never
                        // accept another turn against an implicitly reset runtime.
                        if failed {
                            break;
                        }
                    }
                    drop(runtime); // release parent and any handler-owned child
                });
                owner_control.cancel();
                owner_busy.store(false, Ordering::Release);
            })?;
        Ok(Self {
            sender,
            control,
            busy,
            initialized,
            thread: Some(thread),
            children,
        })
    }

    /// At most one accepted exchange, including one waiting for initialization.
    /// The receiver is an acknowledgement, not a retry token: losing it never
    /// authorizes replay. Durable IDs remain the journal/ledger's responsibility.
    pub fn submit(&self, bytes: &[u8]) -> Result<mpsc::Receiver<Reply>, String> {
        self.control.check().map_err(|e| e.to_string())?;
        if bytes.is_empty() || bytes.len() > crate::parent_mailbox::MAX_FRAME_BYTES {
            return Err("parent input exceeds owner bound".into());
        }
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "parent exchange already active")?;
        let (reply, receiver) = mpsc::sync_channel(1);
        if self
            .sender
            .try_send(Command {
                bytes: bytes.into(),
                reply,
            })
            .is_err()
        {
            self.busy.store(false, Ordering::Release);
            return Err("parent owner unavailable".into());
        }
        Ok(receiver)
    }

    pub fn cancel(&self) {
        self.control.cancel();
    }

    /// Exact child cancellation request, never a parent stop or join receipt.
    pub fn cancel_child(
        &self,
        identity: &crate::parent_child_control::Identity,
    ) -> Result<(), String> {
        self.control.check().map_err(|error| error.to_string())?;
        self.children
            .as_ref()
            .ok_or("owner has no child cancellation contract")?
            .cancel(identity)
            .map_err(str::to_owned)
    }

    /// Live observation, not a reservation or guarantee a later submit succeeds.
    pub fn status(&self) -> OwnerStatus {
        if self.is_finished() {
            OwnerStatus::ContextLost
        } else if self.control.check().is_err() {
            OwnerStatus::Stopping
        } else if !self.initialized.load(Ordering::Acquire) {
            OwnerStatus::Initializing
        } else if self.busy.load(Ordering::Acquire) {
            OwnerStatus::TurnActive
        } else {
            OwnerStatus::Ready
        }
    }

    /// Observation only: join is still required to confirm teardown and reclaim
    /// host reservations. A finished thread never implies resumable context.
    pub fn is_finished(&self) -> bool {
        self.thread
            .as_ref()
            .map_or(true, |thread| thread.is_finished())
    }

    /// Confirm owner exit, not just cancellation requested. Only a successful
    /// join proves the handler and its owned resources have been dropped.
    pub fn stop_and_join(mut self) -> Result<(), String> {
        self.cancel();
        self.thread
            .take()
            .unwrap()
            .join()
            .map_err(|_| "parent owner panicked; reconcile context loss".into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerStatus {
    Initializing,
    Ready,
    TurnActive,
    Stopping,
    ContextLost,
}

impl Drop for ParentOwner {
    fn drop(&mut self) {
        self.control.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readiness_tracks_constructor_active_turn_and_cancellation() {
        let (initialize, initialization) = mpsc::sync_channel(1);
        let (started, active) = mpsc::sync_channel(1);
        let (release, work) = mpsc::sync_channel(1);
        let owner = ParentOwner::spawn(Duration::from_secs(10), move || {
            initialization.recv().unwrap();
            Ok(move |_: &[u8]| {
                started.send(()).unwrap();
                work.recv().unwrap();
                Ok(vec![1])
            })
        })
        .unwrap();
        assert_eq!(owner.status(), OwnerStatus::Initializing);
        initialize.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while owner.status() != OwnerStatus::Ready {
            assert!(std::time::Instant::now() < deadline);
            thread::yield_now();
        }
        let response = owner.submit(b"turn").unwrap();
        active.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(owner.status(), OwnerStatus::TurnActive);
        owner.cancel();
        assert_eq!(owner.status(), OwnerStatus::Stopping);
        release.send(()).unwrap();
        assert!(response
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .is_err());
        owner.stop_and_join().unwrap();
    }

    #[test]
    fn failed_initialization_never_reports_ready() {
        type Handler = fn(&[u8]) -> Reply;
        let owner = ParentOwner::spawn(Duration::from_secs(2), || -> Result<Handler, String> {
            Err("admitted runtime failed to start".into())
        })
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match owner.status() {
                OwnerStatus::ContextLost => break,
                OwnerStatus::Initializing | OwnerStatus::Stopping => {}
                status => panic!("failed initialization reported {status:?}"),
            }
            assert!(std::time::Instant::now() < deadline);
            thread::yield_now();
        }
        assert!(owner.submit(b"turn").is_err());
        owner.stop_and_join().unwrap();
    }
    struct Resource(mpsc::SyncSender<()>);
    impl Drop for Resource {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    #[test]
    fn acknowledged_turn_is_ready_for_immediate_next_submission() {
        let owner = ParentOwner::spawn(Duration::from_secs(10), || {
            Ok(|bytes: &[u8]| Ok(bytes.to_vec()))
        })
        .unwrap();
        for _ in 0..1000 {
            let reply = owner.submit(b"turn").unwrap();
            assert_eq!(
                reply.recv_timeout(Duration::from_secs(2)).unwrap().unwrap(),
                b"turn"
            );
        }
        owner.stop_and_join().unwrap();
    }
    #[test]
    fn idle_expiry_drops_retained_runtime_without_another_request() {
        let (dropped, observe) = mpsc::sync_channel(1);
        let owner = ParentOwner::spawn(Duration::from_millis(40), move || {
            let resource = Resource(dropped);
            Ok(move |_: &[u8]| {
                let _ = &resource;
                Ok(vec![1])
            })
        })
        .unwrap();
        observe.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(owner.submit(b"stale").is_err());
        owner.stop_and_join().unwrap();
    }

    #[test]
    fn cancellation_interrupts_active_control_aware_work_and_confirms_drop() {
        let (started, ready) = mpsc::sync_channel(1);
        let (dropped, observe) = mpsc::sync_channel(1);
        let owner = ParentOwner::spawn(Duration::from_secs(10), move || {
            let resource = Resource(dropped);
            Ok(move |_: &[u8]| {
                let _ = &resource;
                started.send(()).unwrap();
                loop {
                    celln_control::check().map_err(|e| e.to_string())?;
                    thread::yield_now();
                }
            })
        })
        .unwrap();
        let reply = owner.submit(b"work").unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(owner.submit(b"overlap").is_err());
        owner.cancel();
        assert!(reply.recv_timeout(Duration::from_secs(2)).unwrap().is_err());
        owner.stop_and_join().unwrap();
        observe.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn handler_failure_does_not_recreate_context() {
        let owner = ParentOwner::spawn(Duration::from_secs(1), || {
            Ok(|_: &[u8]| Err("context lost".into()))
        })
        .unwrap();
        assert_eq!(
            owner
                .submit(b"work")
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap_err(),
            "context lost"
        );
        owner.stop_and_join().unwrap();
    }
}
