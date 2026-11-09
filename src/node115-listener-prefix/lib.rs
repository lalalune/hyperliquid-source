//! Selected consensus-listener frame limits joined to its fresh typed prefix.
//! A decoded prefix is not a fully decoded or authenticated message.
use node115_frame_stream::{FrameError, FrameReader, Status as FrameStatus};
use node115_u32_varint::{ReadError, read_u32};

/// Bound specifically to listener0x2af8be0, not asserted for other callers.
pub const LISTENER_LIMIT: u64 = 11_000_000;

#[derive(Debug)]
pub struct Prefix {
    pub identity: [u8; 20],
    pub kind: u32,
    pub frame: Vec<u8>,
    pub body_offset: usize,
    pub charged: u64,
}
impl Prefix {
    pub fn body(&self) -> &[u8] {
        &self.frame[self.body_offset..]
    }
}

#[derive(Debug)]
pub enum PrefixError {
    AddressUnexpectedEnd { deficit: usize },
    Kind(ReadError),
}
#[derive(Debug)]
pub struct PrefixFailure {
    pub error: PrefixError,
    pub frame: Vec<u8>,
    pub consumed: usize,
    pub charged: u64,
}

/// The selected wrapper constructs a new limited reader with charged=0 each call.
/// This entrypoint takes already decoded bytes; it does not enforce a wire length.
/// It stops after the20-byte identity and u32 kind, before kind/body validation.
pub fn decode_prefix(frame: Vec<u8>) -> Result<Prefix, PrefixFailure> {
    // 0x2cd7d20: mode1 charges20 before checking availability. The fresh native
    // reader has count0 and limit11m, so overflow/limit failure is unreachable here.
    let mut charged = 20;
    if frame.len() < 20 {
        return Err(PrefixFailure {
            error: PrefixError::AddressUnexpectedEnd {
                deficit: 20 - frame.len(),
            },
            frame,
            consumed: 0,
            charged,
        });
    }
    let mut identity = [0; 20];
    identity.copy_from_slice(&frame[..20]);
    let mut remaining = &frame[20..];
    let kind = read_u32(&mut remaining, 1, LISTENER_LIMIT, &mut charged);
    let consumed = frame.len() - remaining.len();
    match kind {
        Ok(kind) => Ok(Prefix {
            identity,
            kind,
            frame,
            body_offset: consumed,
            charged,
        }),
        Err(error) => Err(PrefixFailure {
            error: PrefixError::Kind(error),
            frame,
            consumed,
            charged,
        }),
    }
}

#[derive(Debug)]
pub enum Status {
    Pending,
    Prefix(Prefix),
    FrameFailed(FrameError),
    PrefixFailed(PrefixFailure),
}
#[derive(Debug)]
pub struct Outcome {
    /// Input bytes consumed by the one-frame adapter, excluding any next frame.
    pub consumed: usize,
    pub status: Status,
}

/// Offline one-frame adapter. Terminal/EOF policy is inherited from FrameReader;
/// it is not a reconstruction of connection reuse, cancellation or shutdown.
pub struct ListenerPrefixReader {
    frame: FrameReader,
}
impl Default for ListenerPrefixReader {
    fn default() -> Self {
        Self::new()
    }
}
impl ListenerPrefixReader {
    pub fn new() -> Self {
        Self {
            frame: FrameReader::new(LISTENER_LIMIT),
        }
    }
    pub fn feed(&mut self, input: &[u8]) -> Outcome {
        let outcome = self.frame.feed(input);
        Self::convert(outcome.consumed, outcome.status)
    }
    pub fn eof(&mut self) -> Outcome {
        let outcome = self.frame.eof();
        Self::convert(outcome.consumed, outcome.status)
    }
    fn convert(consumed: usize, status: FrameStatus) -> Outcome {
        let status = match status {
            FrameStatus::Pending => Status::Pending,
            FrameStatus::Failed(error) => Status::FrameFailed(error),
            FrameStatus::Complete(bytes) => match decode_prefix(bytes) {
                Ok(prefix) => Status::Prefix(prefix),
                Err(error) => Status::PrefixFailed(error),
            },
        };
        Outcome { consumed, status }
    }
}
