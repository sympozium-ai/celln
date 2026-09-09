//! Optional parent transport v1. This transports untrusted data, not authority.
//! RX returns a u32 LE length then payload (0xff bytes when empty); TX accumulates a response; COMMIT
//! accepts exactly one byte equal to 1 and yields the VM to its host owner.
//! A protocol violation permanently poisons the mailbox. No implicit reset or
//! overwrite can hide a malformed request or replay an unfinished exchange.

use std::collections::VecDeque;

pub const RX: u16 = 0x520;
pub const TX: u16 = 0x521;
pub const COMMIT: u16 = 0x522;
pub const MAX_FRAME_BYTES: usize = 8192;

#[derive(Debug, Default)]
pub struct ParentMailbox {
    input: VecDeque<u8>,
    output: Vec<u8>,
    active: bool,
    committed: bool,
    poisoned: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid parent mailbox state or frame")]
pub struct MailboxError;

impl ParentMailbox {
    /// Host delivery; rejects busy/invalid input without changing the exchange.
    pub fn deliver(&mut self, bytes: &[u8]) -> Result<(), MailboxError> {
        if self.poisoned || self.active || bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(MailboxError);
        }
        self.input.extend((bytes.len() as u32).to_le_bytes());
        self.input.extend(bytes);
        self.active = true;
        Ok(())
    }

    pub fn read(&mut self, data: &mut [u8]) {
        for b in data {
            *b = if self.poisoned {
                None
            } else {
                self.input.pop_front()
            }
            .unwrap_or(0xff);
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        if self.poisoned
            || !self.active
            || self.committed
            || !self.input.is_empty()
            || data.len() > MAX_FRAME_BYTES.saturating_sub(self.output.len())
        {
            self.poisoned = true;
            return;
        }
        self.output.extend_from_slice(data);
    }

    /// Always yields, including on malformed commit. The owner must inspect
    /// take_response before resuming; poisoned exchanges never produce data.
    pub fn commit(&mut self, data: &[u8]) {
        if data != [1]
            || !self.active
            || self.committed
            || !self.input.is_empty()
            || self.output.is_empty()
        {
            self.poisoned = true;
        }
        self.committed = true;
    }

    pub fn take_response(&mut self) -> Result<Option<Vec<u8>>, MailboxError> {
        if self.poisoned {
            return Err(MailboxError);
        }
        if !self.committed {
            return Ok(None);
        }
        self.active = false;
        self.committed = false;
        Ok(Some(std::mem::take(&mut self.output)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> ParentMailbox {
        let mut m = ParentMailbox::default();
        m.deliver(b"hi").unwrap();
        let mut frame = [0; 6];
        m.read(&mut frame);
        assert_eq!(&frame, b"\x02\0\0\0hi");
        m
    }

    #[test]
    fn idle_word_poll_does_not_consume_a_later_frame_prefix() {
        let mut mailbox = ParentMailbox::default();
        let mut word = [0; 2];
        mailbox.read(&mut word);
        assert_eq!(word, [0xff; 2]);
        mailbox.deliver(b"hello").unwrap();
        mailbox.read(&mut word);
        assert_eq!(u16::from_le_bytes(word), 5);
        mailbox.read(&mut word);
        assert_eq!(word, [0; 2]);
        let mut payload = [0; 5];
        mailbox.read(&mut payload);
        assert_eq!(&payload, b"hello");
    }
    #[test]
    fn serial_exchanges_do_not_overwrite_or_replay() {
        let mut m = ready();
        assert!(m.deliver(b"overwrite").is_err());
        assert_eq!(m.take_response().unwrap(), None);
        m.write(b"one");
        m.commit(&[1]);
        assert!(m.deliver(b"overwrite").is_err());
        assert_eq!(m.take_response().unwrap().unwrap(), b"one");
        assert_eq!(m.take_response().unwrap(), None);
        m.deliver(b"two").unwrap();
        m.read(&mut [0; 7]);
        m.write(b"second");
        m.commit(&[1]);
        assert_eq!(m.take_response().unwrap().unwrap(), b"second");
    }

    #[test]
    fn overflow_cannot_execute_a_valid_prefix() {
        let mut m = ready();
        m.write(&[b'x'; MAX_FRAME_BYTES]);
        m.write(b"x");
        m.commit(&[1]);
        assert_eq!(m.output.len(), MAX_FRAME_BYTES);
        assert_eq!(m.take_response(), Err(MailboxError));
        assert!(m.deliver(b"retry").is_err());
    }

    #[test]
    fn malformed_and_premature_commits_poison_permanently() {
        for bytes in [&[][..], &[0][..], &[1, 1][..]] {
            let mut m = ready();
            m.write(b"valid prefix");
            m.commit(bytes);
            assert_eq!(m.take_response(), Err(MailboxError));
        }
        let mut m = ParentMailbox::default();
        m.deliver(b"unread").unwrap();
        m.write(b"premature");
        m.commit(&[1]);
        assert_eq!(m.take_response(), Err(MailboxError));
        let mut m = ready();
        m.commit(&[1]);
        assert_eq!(m.take_response(), Err(MailboxError));
    }

    #[test]
    fn host_input_bounds_and_duplicate_commit() {
        let mut m = ParentMailbox::default();
        assert!(m.deliver(b"").is_err());
        assert!(m.deliver(&[0; MAX_FRAME_BYTES + 1]).is_err());
        m.deliver(&[0; MAX_FRAME_BYTES]).unwrap();
        let mut m = ready();
        m.write(b"ok");
        m.commit(&[1]);
        m.commit(&[1]);
        assert_eq!(m.take_response(), Err(MailboxError));
    }
}
