//! Offline stream adapter joining the independently reconstructed node115
//! frame policy and size-prefixed LZ4 decoder.
//!
//! This is a new `std::io::Read` API, not the captured async future or ABI.
//! It never opens a socket. See the work-item packet for the limits of the
//! target-derived and host-defined behavior.
#![forbid(unsafe_code)]

use std::io::{ErrorKind, Read};

use node115_lz4_decode::{decode, DecodeError};
use node115_tcp_frame_plan::{admit, decode_header, next_chunk, OverLimit};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum outer payload length admitted by the captured frame policy.
    pub frame_payload: u64,
    /// Maximum decoded capacity admitted by the LZ4 adapter.
    pub decoded_capacity: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadStage {
    Header,
    Payload,
}

/// Describes whether the caller can continue parsing this byte stream.
///
/// `NoFrameBytesConsumed` means an I/O error occurred before any byte from a
/// frame was consumed; callers can retry from the same stream position if the
/// underlying error is retryable. `NextFrameBoundary` means the whole frame
/// was consumed, even though post-read decompression failed. In all other
/// error cases the frame is incomplete or intentionally undrained and the
/// stream must be discarded to avoid parsing payload bytes as a new header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamDisposition {
    NoFrameBytesConsumed,
    NextFrameBoundary,
    DiscardStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameErrorKind {
    OverLimit(OverLimit),
    Allocation,
    Io { stage: ReadStage, kind: ErrorKind },
    Lz4(DecodeError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameError {
    pub kind: FrameErrorKind,
    /// Number of bytes consumed from this frame before the error was returned.
    pub bytes_consumed: u64,
    pub disposition: StreamDisposition,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    /// Raw payload when the flag is not exactly one; decoded payload otherwise.
    pub payload: Vec<u8>,
    pub was_compressed: bool,
}

/// Read one five-byte-header frame from a caller-owned stream.
///
/// Header and payload reads tolerate short reads and retry `Interrupted`.
/// The frame plan's 4,000,000-byte interval cap is applied to payload reads.
/// Over-limit frames are not drained. If the payload is compressed, the full
/// frame is consumed before `decode` runs, so an LZ4 error leaves the stream at
/// the next frame boundary.
///
/// This composes two target-bound policies, but `Read`, short-read handling,
/// allocation behavior and stream disposition are this adapter's API; they
/// are not claims about the captured async reader's complete error lifecycle.
pub fn read_frame<R: Read>(reader: &mut R, limits: Limits) -> Result<Option<Frame>, FrameError> {
    let mut header_bytes = [0u8; 5];
    let header_read = match fill(reader, &mut header_bytes, ReadStage::Header, 0) {
        Ok(0) => return Ok(None),
        Ok(read) => read,
        Err(error) => return Err(error),
    };
    debug_assert_eq!(header_read, header_bytes.len());

    let header = decode_header(&header_bytes);
    let plan = admit(header, limits.frame_payload).map_err(|kind| FrameError {
        kind: FrameErrorKind::OverLimit(kind),
        bytes_consumed: header_bytes.len() as u64,
        disposition: StreamDisposition::DiscardStream,
    })?;

    let payload_len = plan.payload_len as usize;
    let mut wire_payload = Vec::new();
    wire_payload
        .try_reserve_exact(payload_len)
        .map_err(|_| FrameError {
            kind: FrameErrorKind::Allocation,
            bytes_consumed: header_bytes.len() as u64,
            disposition: StreamDisposition::DiscardStream,
        })?;
    wire_payload.resize(payload_len, 0);

    let mut completed = 0usize;
    while let Some((start, end)) = next_chunk(plan.payload_len, completed as u64) {
        debug_assert_eq!(start as usize, completed);
        let interval_end = end as usize;
        let read = fill(
            reader,
            &mut wire_payload[completed..interval_end],
            ReadStage::Payload,
            header_bytes.len() as u64 + completed as u64,
        )?;
        completed += read;
        debug_assert_eq!(completed, interval_end);
    }

    if plan.decompress_after_read {
        let payload =
            decode(&wire_payload, limits.decoded_capacity).map_err(|kind| FrameError {
                kind: FrameErrorKind::Lz4(kind),
                bytes_consumed: header_bytes.len() as u64 + plan.payload_len as u64,
                disposition: StreamDisposition::NextFrameBoundary,
            })?;
        Ok(Some(Frame {
            payload,
            was_compressed: true,
        }))
    } else {
        Ok(Some(Frame {
            payload: wire_payload,
            was_compressed: false,
        }))
    }
}

/// Fill the supplied slice, preserving the exact consumed count on failure.
/// An empty header at EOF is distinguished by the caller from a truncated one.
fn fill<R: Read>(
    reader: &mut R,
    output: &mut [u8],
    stage: ReadStage,
    prior_bytes: u64,
) -> Result<usize, FrameError> {
    let mut filled = 0usize;
    while filled < output.len() {
        match reader.read(&mut output[filled..]) {
            Ok(0) => {
                if filled == 0 && prior_bytes == 0 && stage == ReadStage::Header {
                    return Ok(0);
                }
                return Err(FrameError {
                    kind: FrameErrorKind::Io {
                        stage,
                        kind: ErrorKind::UnexpectedEof,
                    },
                    bytes_consumed: prior_bytes + filled as u64,
                    disposition: if prior_bytes + filled as u64 == 0 {
                        StreamDisposition::NoFrameBytesConsumed
                    } else {
                        StreamDisposition::DiscardStream
                    },
                });
            }
            Ok(count) => filled += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(FrameError {
                    kind: FrameErrorKind::Io {
                        stage,
                        kind: error.kind(),
                    },
                    bytes_consumed: prior_bytes + filled as u64,
                    disposition: if prior_bytes + filled as u64 == 0 {
                        StreamDisposition::NoFrameBytesConsumed
                    } else {
                        StreamDisposition::DiscardStream
                    },
                });
            }
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::min;
    use std::io::{self, Cursor};

    #[derive(Debug)]
    struct Segmented {
        bytes: Vec<u8>,
        cursor: usize,
        segments: Vec<usize>,
        calls: usize,
        fail_at: Option<(usize, ErrorKind)>,
        interrupt_once: bool,
        requested: Vec<usize>,
    }

    impl Segmented {
        fn new(bytes: Vec<u8>, segments: Vec<usize>) -> Self {
            Self {
                bytes,
                cursor: 0,
                segments,
                calls: 0,
                fail_at: None,
                interrupt_once: false,
                requested: Vec::new(),
            }
        }

        fn failing_at(mut self, offset: usize, kind: ErrorKind) -> Self {
            self.fail_at = Some((offset, kind));
            self
        }

        fn interrupt_once(mut self) -> Self {
            self.interrupt_once = true;
            self
        }
    }

    impl Read for Segmented {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.requested.push(output.len());
            if self.interrupt_once {
                self.interrupt_once = false;
                self.calls += 1;
                return Err(io::Error::new(ErrorKind::Interrupted, "scripted interrupt"));
            }
            if let Some((offset, kind)) = self.fail_at {
                if self.cursor == offset {
                    return Err(io::Error::new(kind, "scripted read failure"));
                }
            }
            let segment = self.segments.get(self.calls).copied().unwrap_or(usize::MAX);
            self.calls += 1;
            let available = self.bytes.len().saturating_sub(self.cursor);
            let before_failure = self
                .fail_at
                .map(|(offset, _)| offset.saturating_sub(self.cursor))
                .unwrap_or(usize::MAX);
            let count = min(output.len(), min(segment, min(available, before_failure)));
            if count == 0 {
                return Ok(0);
            }
            output[..count].copy_from_slice(&self.bytes[self.cursor..self.cursor + count]);
            self.cursor += count;
            Ok(count)
        }
    }

    fn header(payload: &[u8], flag: u8) -> Vec<u8> {
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.push(flag);
        frame.extend_from_slice(payload);
        frame
    }

    fn limits(frame_payload: u64, decoded_capacity: u64) -> Limits {
        Limits {
            frame_payload,
            decoded_capacity,
        }
    }

    #[test]
    fn assembles_partial_header_and_payload_reads() {
        let bytes = header(b"abcdef", 0);
        let mut reader = Segmented::new(bytes, vec![1, 2, 1, 1, 2, 1, 3, 1]);
        let frame = read_frame(&mut reader, limits(6, 6)).unwrap().unwrap();
        assert_eq!(frame.payload, b"abcdef");
        assert!(!frame.was_compressed);
        assert_eq!(reader.cursor, 11);
    }

    #[test]
    fn exact_limit_is_admitted_and_over_limit_does_not_consume_payload() {
        let bytes = header(b"abcd", 7);
        let mut exact = Cursor::new(bytes.clone());
        assert_eq!(
            read_frame(&mut exact, limits(4, 4))
                .unwrap()
                .unwrap()
                .payload,
            b"abcd"
        );

        let mut over = Cursor::new(bytes);
        let error = read_frame(&mut over, limits(3, 4)).unwrap_err();
        assert_eq!(error.kind, FrameErrorKind::OverLimit(OverLimit));
        assert_eq!(error.bytes_consumed, 5);
        assert_eq!(error.disposition, StreamDisposition::DiscardStream);
        assert_eq!(over.position(), 5);
    }

    #[test]
    fn joins_flag_one_to_lz4_and_leaves_the_next_frame_readable() {
        let compressed = [8, 0, 0, 0, 0x13, b'A', 1, 0, 0];
        let mut bytes = header(&compressed, 1);
        bytes.extend(header(b"Z", 0));
        let mut reader = Segmented::new(bytes, vec![1, 2, 1, 3, 2, 1, 4]);

        let decoded = read_frame(&mut reader, limits(32, 8)).unwrap().unwrap();
        assert_eq!(decoded.payload, vec![b'A'; 8]);
        assert!(decoded.was_compressed);
        let next = read_frame(&mut reader, limits(1, 1)).unwrap().unwrap();
        assert_eq!(next.payload, b"Z");
    }

    #[test]
    fn lz4_error_after_full_payload_keeps_the_stream_at_a_frame_boundary() {
        let mut bytes = header(&[4, 0, 0, 0], 1);
        bytes.extend(header(b"N", 0));
        let mut reader = Cursor::new(bytes);
        let error = read_frame(&mut reader, limits(4, 8)).unwrap_err();
        assert_eq!(error.kind, FrameErrorKind::Lz4(DecodeError::Input));
        assert_eq!(error.disposition, StreamDisposition::NextFrameBoundary);
        assert_eq!(error.bytes_consumed, 9);
        assert_eq!(
            read_frame(&mut reader, limits(1, 1))
                .unwrap()
                .unwrap()
                .payload,
            b"N"
        );
    }

    #[test]
    fn truncated_payload_marks_the_stream_for_discard() {
        let bytes = header(b"a", 0);
        let mut truncated = bytes;
        truncated[..4].copy_from_slice(&3u32.to_be_bytes());
        let mut reader = Cursor::new(truncated);
        let error = read_frame(&mut reader, limits(3, 3)).unwrap_err();
        assert_eq!(
            error.kind,
            FrameErrorKind::Io {
                stage: ReadStage::Payload,
                kind: ErrorKind::UnexpectedEof
            }
        );
        assert_eq!(error.bytes_consumed, 6);
        assert_eq!(error.disposition, StreamDisposition::DiscardStream);
    }

    #[test]
    fn io_error_before_the_header_consumes_no_frame_bytes() {
        let mut reader =
            Segmented::new(b"unused".to_vec(), vec![]).failing_at(0, ErrorKind::ConnectionReset);
        let error = read_frame(&mut reader, limits(8, 8)).unwrap_err();
        assert_eq!(
            error.kind,
            FrameErrorKind::Io {
                stage: ReadStage::Header,
                kind: ErrorKind::ConnectionReset
            }
        );
        assert_eq!(error.bytes_consumed, 0);
        assert_eq!(error.disposition, StreamDisposition::NoFrameBytesConsumed);
        assert_eq!(reader.cursor, 0);
    }

    #[test]
    fn interrupted_reads_retry_without_losing_frame_bytes() {
        let mut reader = Segmented::new(header(b"ok", 0), vec![usize::MAX]).interrupt_once();
        let frame = read_frame(&mut reader, limits(2, 2)).unwrap().unwrap();
        assert_eq!(frame.payload, b"ok");
        assert_eq!(reader.cursor, 7);
    }

    #[test]
    fn payload_io_error_after_partial_consumption_requires_stream_discard() {
        let mut reader = Segmented::new(header(b"abc", 0), vec![usize::MAX])
            .failing_at(7, ErrorKind::ConnectionReset);
        let error = read_frame(&mut reader, limits(3, 3)).unwrap_err();
        assert_eq!(
            error.kind,
            FrameErrorKind::Io {
                stage: ReadStage::Payload,
                kind: ErrorKind::ConnectionReset
            }
        );
        assert_eq!(error.bytes_consumed, 7);
        assert_eq!(error.disposition, StreamDisposition::DiscardStream);
    }

    #[test]
    fn clean_eof_and_zero_length_frames_are_distinct() {
        let mut reader = Cursor::new(header(&[], 0));
        assert_eq!(
            read_frame(&mut reader, limits(0, 0))
                .unwrap()
                .unwrap()
                .payload,
            b""
        );
        assert_eq!(read_frame(&mut reader, limits(0, 0)).unwrap(), None);
    }

    #[test]
    fn payload_reads_follow_the_four_million_byte_interval_cap() {
        let payload = vec![0x5a; 4_000_001];
        let mut reader = Segmented::new(header(&payload, 0), vec![usize::MAX]);
        let frame = read_frame(&mut reader, limits(4_000_001, 0))
            .unwrap()
            .unwrap();
        assert_eq!(frame.payload.len(), 4_000_001);
        assert!(reader
            .requested
            .iter()
            .skip(1)
            .all(|requested| *requested <= 4_000_000));
    }
}
