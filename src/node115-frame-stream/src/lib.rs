//! An owned, offline, one-frame harness for the selected node #115 policy.
//!
//! This is not the original async future or a socket implementation. The caller
//! supplies byte fragments and signals EOF explicitly; native scheduling,
//! timeout, error payloads and allocator ABI remain outside this interface.

use node115_lz4_decode::{decode, DecodeError};
use node115_tcp_frame_plan::{admit, decode_header, next_chunk, Plan};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    OverLimit,
    EarlyEof,
    Decode(DecodeError),
    Allocation,
    AlreadyTerminal,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Pending,
    Complete(Vec<u8>),
    Failed(FrameError),
}

/// Number of supplied bytes consumed, and the outcome after consuming them.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub consumed: usize,
    pub status: Status,
}

enum State {
    Header { bytes: [u8; 5], used: usize },
    Body { plan: Plan, bytes: Vec<u8> },
    Terminal,
}

/// One frame only. Once complete or failed, create another reader for the
/// next frame. This explicit local policy does not claim native connection reuse.
pub struct FrameReader {
    maximum: u64,
    state: State,
}

impl FrameReader {
    pub fn new(maximum: u64) -> Self {
        Self {
            maximum,
            state: State::Header {
                bytes: [0; 5],
                used: 0,
            },
        }
    }

    /// Supply bytes without implying EOF. An empty slice is a no-progress event.
    /// Bytes following a complete frame are left unconsumed for the caller.
    pub fn feed(&mut self, input: &[u8]) -> Outcome {
        let mut consumed = 0;
        loop {
            match &mut self.state {
                State::Terminal => {
                    return Outcome {
                        consumed,
                        status: Status::Failed(FrameError::AlreadyTerminal),
                    }
                }
                State::Header { bytes, used } => {
                    let take = (5 - *used).min(input.len() - consumed);
                    bytes[*used..*used + take].copy_from_slice(&input[consumed..consumed + take]);
                    *used += take;
                    consumed += take;
                    if *used < 5 {
                        return Outcome {
                            consumed,
                            status: Status::Pending,
                        };
                    }
                    let plan = match admit(decode_header(bytes), self.maximum) {
                        Ok(plan) => plan,
                        Err(_) => {
                            self.state = State::Terminal;
                            return Outcome {
                                consumed,
                                status: Status::Failed(FrameError::OverLimit),
                            };
                        }
                    };
                    let mut body = Vec::new();
                    if body.try_reserve_exact(plan.payload_len as usize).is_err() {
                        self.state = State::Terminal;
                        return Outcome {
                            consumed,
                            status: Status::Failed(FrameError::Allocation),
                        };
                    }
                    self.state = State::Body { plan, bytes: body };
                }
                State::Body { plan, bytes } => {
                    if let Some((start, end)) = next_chunk(plan.payload_len, bytes.len() as u64) {
                        let take = ((end - start) as usize).min(input.len() - consumed);
                        bytes.extend_from_slice(&input[consumed..consumed + take]);
                        consumed += take;
                        if bytes.len() < plan.payload_len as usize && consumed == input.len() {
                            return Outcome {
                                consumed,
                                status: Status::Pending,
                            };
                        }
                    } else {
                        let transformed = if plan.decompress_after_read {
                            decode(bytes, self.maximum).map_err(FrameError::Decode)
                        } else {
                            Ok(std::mem::take(bytes))
                        };
                        self.state = State::Terminal;
                        return Outcome {
                            consumed,
                            status: match transformed {
                                Ok(frame) => Status::Complete(frame),
                                Err(error) => Status::Failed(error),
                            },
                        };
                    }
                }
            }
        }
    }

    /// Signal end of input. Pending frames fail and become terminal.
    pub fn eof(&mut self) -> Outcome {
        let error = if matches!(self.state, State::Terminal) {
            FrameError::AlreadyTerminal
        } else {
            self.state = State::Terminal;
            FrameError::EarlyEof
        };
        Outcome {
            consumed: 0,
            status: Status::Failed(error),
        }
    }
}
