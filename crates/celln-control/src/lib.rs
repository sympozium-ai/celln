//! Host-only cooperative execution control. Context carries no grants: it can
//! only stop work or shorten its lifetime. Scoped installation is thread-local.

use std::cell::RefCell;
use std::io;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

pub mod process;

#[derive(Clone, Debug)]
pub struct Control(Arc<Inner>);
#[derive(Debug)]
struct Inner {
    deadline: Instant,
    stop: AtomicU8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stopped {
    Cancelled,
    Deadline,
}
impl std::fmt::Display for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Cancelled => "execution cancelled",
            Self::Deadline => "execution deadline exceeded",
        })
    }
}

thread_local! { static CURRENT: RefCell<Option<Control>> = const { RefCell::new(None) }; }

impl Control {
    pub fn new(timeout: Duration) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deadline overflow"))?;
        Ok(Self(Arc::new(Inner {
            deadline,
            stop: AtomicU8::new(0),
        })))
    }
    pub fn reason(&self) -> Option<Stopped> {
        if Instant::now() >= self.0.deadline {
            let _ = self
                .0
                .stop
                .compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst);
        }
        match self.0.stop.load(Ordering::SeqCst) {
            1 => Some(Stopped::Cancelled),
            2 => Some(Stopped::Deadline),
            _ => None,
        }
    }
    pub fn cancel(&self) {
        self.reason();
        let _ = self
            .0
            .stop
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
    }
    pub fn check(&self) -> io::Result<()> {
        match self.reason() {
            Some(reason) => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                reason.to_string(),
            )),
            None => Ok(()),
        }
    }
    pub fn remaining(&self) -> Duration {
        self.0.deadline.saturating_duration_since(Instant::now())
    }
    pub fn scope<T>(&self, f: impl FnOnce() -> T) -> T {
        struct Restore(Option<Control>);
        impl Drop for Restore {
            fn drop(&mut self) {
                CURRENT.with(|c| *c.borrow_mut() = self.0.take());
            }
        }
        let _restore = Restore(CURRENT.with(|c| c.replace(Some(self.clone()))));
        f()
    }
}

pub fn current() -> Option<Control> {
    CURRENT.with(|c| c.borrow().clone())
}
pub fn check() -> io::Result<()> {
    current().map_or(Ok(()), |c| c.check())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_is_sticky_and_scope_is_restored() {
        let c = Control::new(Duration::from_secs(10)).unwrap();
        c.scope(|| {
            assert!(current().is_some());
            c.cancel();
            assert!(check().is_err());
        });
        assert!(current().is_none());
        assert_eq!(c.reason(), Some(Stopped::Cancelled));
    }
    #[test]
    fn elapsed_deadline_cannot_be_relabelled_as_cancellation() {
        let c = Control::new(Duration::ZERO).unwrap();
        c.cancel();
        assert_eq!(c.reason(), Some(Stopped::Deadline));
    }
}
