//! Owned logical payload receive after a complete five-byte header.
//! Host events model readiness; this is not a native async or socket ABI.
use node115_tcp_frame_plan::{Header, Plan, admit, next_chunk};

#[derive(Debug, PartialEq, Eq)]
pub enum InitError {
    OverLimit,
    Allocation,
}

/// Inputs are supplied by the host; Pending and Timeout are not native raw tags.
#[derive(Debug, PartialEq, Eq)]
pub enum Event<'a, E> {
    Pending,
    Bytes(&'a [u8]),
    Error(E),
    Timeout,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome<E> {
    Pending,
    Progress,
    Complete {
        payload: Vec<u8>,
        decompress_after_read: bool,
    },
    Eof,
    Error(E),
    Timeout,
    InvalidHostInput,
    Finished,
}

pub struct Receiver {
    plan: Plan,
    buffer: Option<Vec<u8>>,
    outer_completed: u64,
    chunk_end: u64,
    chunk_filled: u64,
    waiting: bool,
}

impl Receiver {
    /// The supplied header must already be read. Allocation failures are host
    /// errors; no native allocator or cancellation behavior is claimed.
    pub fn new(header: Header, maximum: u64) -> Result<Self, InitError> {
        let plan = admit(header, maximum).map_err(|_| InitError::OverLimit)?;
        let len = plan.payload_len as usize;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(len)
            .map_err(|_| InitError::Allocation)?;
        buffer.resize(len, 0);
        let chunk_end = next_chunk(plan.payload_len, 0).map_or(0, |(_, end)| end);
        Ok(Self {
            plan,
            buffer: Some(buffer),
            outer_completed: 0,
            chunk_end,
            chunk_filled: 0,
            waiting: false,
        })
    }

    pub fn outer_completed(&self) -> u64 {
        self.outer_completed
    }
    pub fn chunk_filled(&self) -> u64 {
        self.chunk_filled
    }
    pub fn chunk_remaining(&self) -> u64 {
        self.chunk_end - self.outer_completed - self.chunk_filled
    }
    pub fn is_live(&self) -> bool {
        self.buffer.is_some()
    }

    /// Process one host event. Bytes must fit the current requested chunk.
    /// Nonempty partial progress remains within that chunk; only a completed
    /// chunk advances the outer counter. Terminal failures discard the buffer.
    pub fn step<E>(&mut self, event: Event<'_, E>) -> Outcome<E> {
        if self.buffer.is_none() {
            return Outcome::Finished;
        }
        if self.outer_completed == u64::from(self.plan.payload_len) {
            return Outcome::Complete {
                payload: self.buffer.take().unwrap(),
                decompress_after_read: self.plan.decompress_after_read,
            };
        }
        match event {
            Event::Pending => {
                self.waiting = true;
                Outcome::Pending
            }
            Event::Timeout => {
                self.buffer.take();
                if self.waiting {
                    Outcome::Timeout
                } else {
                    Outcome::InvalidHostInput
                }
            }
            Event::Error(error) => {
                self.buffer.take();
                Outcome::Error(error)
            }
            Event::Bytes(bytes) => {
                self.waiting = false;
                if bytes.is_empty() {
                    self.buffer.take();
                    return Outcome::Eof;
                }
                if bytes.len() as u64 > self.chunk_remaining() {
                    self.buffer.take();
                    return Outcome::InvalidHostInput;
                }
                let start = (self.outer_completed + self.chunk_filled) as usize;
                self.buffer.as_mut().unwrap()[start..start + bytes.len()].copy_from_slice(bytes);
                self.chunk_filled += bytes.len() as u64;
                if self.chunk_remaining() == 0 {
                    self.outer_completed = self.chunk_end;
                    self.chunk_filled = 0;
                    if self.outer_completed == u64::from(self.plan.payload_len) {
                        return Outcome::Complete {
                            payload: self.buffer.take().unwrap(),
                            decompress_after_read: self.plan.decompress_after_read,
                        };
                    }
                    self.chunk_end = next_chunk(self.plan.payload_len, self.outer_completed)
                        .unwrap()
                        .1;
                }
                Outcome::Progress
            }
        }
    }
}
