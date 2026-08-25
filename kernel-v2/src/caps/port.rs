//! Ports: bounded FIFO message queues.
//!
//! A port is the abstract representation of the whitepaper's
//! dynamically-bound lock-free memory rings: a bounded queue whose
//! depth is part of its ghost state.  `send` takes the message by value
//! — ownership of the payload moves sender → queue — and `recv` returns
//! it (queue → receiver); the Iris spec states exactly this transfer of
//! ownership via a `port_own` resource.
//!
//! Both operations are total and fail without mutating state:
//! `send` on a full port returns `Err(QueueFull)` and the queue is
//! unchanged; `recv` on an empty port returns `Err(Empty)`.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::cap::TaskId;

/// A message in flight on a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Task that sent the message.
    pub from: TaskId,
    /// Payload bytes.  (Later: capability handles piggy-back here or a
    /// dedicated field is added; the transport's ownership story is the
    /// same either way.)
    pub payload: Vec<u8>,
}

impl Message {
    #[inline]
    pub fn new(from: TaskId, payload: Vec<u8>) -> Self {
        Message { from, payload }
    }
}

/// `Port::send` failure: the queue is at its bound; the message was not
/// accepted and the queue is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendError;

/// `Port::recv` failure: the queue is empty; state unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvError;

/// A bounded FIFO message queue owned by a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    owner: TaskId,
    queue: VecDeque<Message>,
    bound: usize,
}

impl Port {
    /// Create a port owned by `owner` with a maximum queue depth of
    /// `bound` messages.
    #[inline]
    pub fn new(owner: TaskId, bound: usize) -> Self {
        Port {
            owner,
            queue: VecDeque::new(),
            bound,
        }
    }

    #[inline]
    pub fn owner(&self) -> TaskId {
        self.owner
    }

    /// The maximum queue depth.  The invariant `len() <= bound` is
    /// preserved by construction: `send` refuses when `len() == bound`.
    #[inline]
    pub fn bound(&self) -> usize {
        self.bound
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.queue.len() >= self.bound
    }

    /// Enqueue `msg` (ownership moves sender → queue).
    ///
    /// - `Ok(())` iff the queue was below its bound;
    /// - `Err(SendError)` iff the queue was full — in which case the
    ///   queue (and `msg`) are untouched.
    pub fn send(&mut self, msg: Message) -> Result<(), SendError> {
        if self.is_full() {
            return Err(SendError);
        }
        self.queue.push_back(msg);
        Ok(())
    }

    /// Dequeue the head of the queue (ownership moves queue → receiver).
    ///
    /// - `Ok(msg)` with FIFO order preserved;
    /// - `Err(RecvError)` iff the queue was empty — state unchanged.
    pub fn recv(&mut self) -> Result<Message, RecvError> {
        self.queue.pop_front().ok_or(RecvError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(t: u32, b: u8) -> Message {
        Message::new(TaskId(t), alloc::vec![b])
    }

    #[test]
    fn send_then_recv_fifo() {
        let mut p = Port::new(TaskId(1), 4);
        p.send(m(1, 10)).unwrap();
        p.send(m(1, 20)).unwrap();
        p.send(m(1, 30)).unwrap();
        assert_eq!(p.recv().unwrap().payload, alloc::vec![10]);
        assert_eq!(p.recv().unwrap().payload, alloc::vec![20]);
        assert_eq!(p.recv().unwrap().payload, alloc::vec![30]);
        assert!(p.is_empty());
    }

    #[test]
    fn send_never_drops_bounded() {
        let mut p = Port::new(TaskId(1), 2);
        p.send(m(1, 1)).unwrap();
        p.send(m(1, 2)).unwrap();
        assert!(p.is_full());
        let before = p.clone();
        // Full port: send errors and leaves the queue unchanged.
        assert_eq!(p.send(m(1, 3)), Err(SendError));
        assert_eq!(p, before);
    }

    #[test]
    fn recv_empty_is_error_and_state_unchanged() {
        let mut p = Port::new(TaskId(1), 2);
        let before = p.clone();
        assert_eq!(p.recv(), Err(RecvError));
        assert_eq!(p, before);
    }

    #[test]
    fn ownership_moves_out_of_queue() {
        let mut p = Port::new(TaskId(1), 2);
        let msg = m(1, 42);
        p.send(msg).unwrap();
        let got = p.recv().unwrap();
        assert_eq!(got.from, TaskId(1));
        assert_eq!(got.payload, alloc::vec![42]);
        // The queue no longer holds it.
        assert!(p.is_empty());
    }

    #[test]
    fn bound_invariant_holds() {
        let mut p = Port::new(TaskId(1), 3);
        for i in 0..100 {
            if p.send(m(1, i as u8)).is_err() {
                break;
            }
        }
        assert!(p.len() <= p.bound());
        assert_eq!(p.len(), 3);
    }
}
