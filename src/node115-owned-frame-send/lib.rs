//! Owned logical sender for the selected prepared-frame path.
//! Host I/O error mapping and allocation behavior are explicit adapter choices.
use node115_tcp_frame_plan::CHUNK_BYTES;
use node115_write_progress::{BOUNDS_FAILURE, CONTINUE, TRANSFORM, advance, charge};
use std::io::{self, Write};

#[derive(Debug, PartialEq, Eq)]
pub enum Poll {
    Pending,
    Complete,
}

pub struct FrameSender {
    frame: Option<Vec<u8>>,
    offset: usize,
    chunk_remaining: usize,
    charged: u64,
    failed: bool,
}

impl FrameSender {
    /// `marker` and already-selected payload are inputs; no compression is performed.
    pub fn new(payload: &[u8], marker: u8) -> io::Result<Self> {
        let size = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload exceeds u32"))?;
        let mut frame = Vec::with_capacity(payload.len().saturating_add(5));
        frame.extend_from_slice(&size.to_be_bytes());
        frame.push(marker);
        frame.extend_from_slice(payload);
        Ok(Self {
            frame: Some(frame),
            offset: 0,
            chunk_remaining: 0,
            charged: 0,
            failed: false,
        })
    }
    pub fn charged(&self) -> u64 {
        self.charged
    }
    pub fn is_released(&self) -> bool {
        self.frame.is_none()
    }

    /// Continue until ready, WouldBlock or error. Mapping a host WouldBlock to
    /// pending is an adapter rule, not a recovered socket/future ABI.
    pub fn poll<W: Write>(&mut self, writer: &mut W) -> io::Result<Poll> {
        loop {
            let Some(frame) = self.frame.as_ref() else {
                return if self.failed {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "sender already failed",
                    ))
                } else {
                    Ok(Poll::Complete)
                };
            };
            if self.offset == frame.len() {
                self.frame = None;
                return Ok(Poll::Complete);
            }
            if self.chunk_remaining == 0 {
                self.chunk_remaining = (frame.len() - self.offset).min(CHUNK_BYTES as usize);
                self.charged = charge(self.charged, self.chunk_remaining as u64);
            }
            let end = self.offset + self.chunk_remaining;
            match writer.write(&frame[self.offset..end]) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Poll::Pending),
                Err(e) => {
                    self.frame = None;
                    self.failed = true;
                    return Err(e);
                }
                Ok(count) => {
                    let next = advance(
                        self.offset as u64,
                        self.chunk_remaining as u64,
                        0,
                        count as u64,
                    );
                    if next.route == BOUNDS_FAILURE || next.route == TRANSFORM {
                        self.frame = None;
                        self.failed = true;
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write made no valid progress",
                        ));
                    }
                    debug_assert_eq!(next.route, CONTINUE);
                    self.offset = next.pointer as usize;
                    self.chunk_remaining = next.remaining as usize;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fragmented {
        output: Vec<u8>,
        max: usize,
        calls: usize,
        pending_at: Option<usize>,
        requests: Vec<usize>,
    }
    impl Write for Fragmented {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            self.requests.push(data.len());
            if self.pending_at == Some(self.calls) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let n = data.len().min(self.max);
            self.output.extend_from_slice(&data[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn short_write_pending_resume_preserves_frame_and_does_not_recharge() {
        let mut s = FrameSender::new(&[7, 8, 9], 0x34).unwrap();
        let mut w = Fragmented {
            output: vec![],
            max: 2,
            calls: 0,
            pending_at: Some(2),
            requests: vec![],
        };
        assert_eq!(s.poll(&mut w).unwrap(), Poll::Pending);
        assert!(!s.is_released());
        assert_eq!(s.charged(), 8);
        assert_eq!(s.poll(&mut w).unwrap(), Poll::Complete);
        assert!(s.is_released());
        assert_eq!(s.charged(), 8);
        assert_eq!(w.output, [0, 0, 0, 3, 0x34, 7, 8, 9]);
    }
    #[test]
    fn multi_chunk_and_empty_payload() {
        for n in [0, 3_999_995, 3_999_996, 4_000_000] {
            let payload = vec![0x5a; n];
            let mut s = FrameSender::new(&payload, 0).unwrap();
            let mut w = Fragmented {
                output: vec![],
                max: usize::MAX,
                calls: 0,
                pending_at: None,
                requests: vec![],
            };
            assert_eq!(s.poll(&mut w).unwrap(), Poll::Complete);
            assert_eq!(&w.output[..4], &(n as u32).to_be_bytes());
            assert_eq!(&w.output[5..], payload);
            assert!(w.requests.iter().all(|x| *x <= 4_000_000));
            assert_eq!(s.charged(), (n + 5) as u64);
        }
    }
    #[test]
    fn zero_progress_releases_frame() {
        for max in [0, 1] {
            let mut s = FrameSender::new(&[1], 1).unwrap();
            let mut w = Fragmented {
                output: vec![],
                max,
                calls: 0,
                pending_at: None,
                requests: vec![],
            };
            if max == 0 {
                assert_eq!(s.poll(&mut w).unwrap_err().kind(), io::ErrorKind::WriteZero);
                assert!(s.is_released());
            } else {
                assert_eq!(s.poll(&mut w).unwrap(), Poll::Complete);
            }
        }
    }
    #[test]
    fn error_after_partial_write_releases_frame() {
        struct Failure {
            calls: usize,
        }
        impl Write for Failure {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls == 1 {
                    Ok(data.len().min(2))
                } else {
                    Err(io::ErrorKind::BrokenPipe.into())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut s = FrameSender::new(&[1, 2, 3], 0).unwrap();
        let mut w = Failure { calls: 0 };
        assert_eq!(
            s.poll(&mut w).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(s.is_released());
    }
    #[test]
    fn pending_in_second_chunk_resumes_without_charging_twice() {
        struct Writer {
            calls: usize,
            output: Vec<u8>,
        }
        impl Write for Writer {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls == 3 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let n = if self.calls == 2 {
                    3.min(data.len())
                } else {
                    data.len()
                };
                self.output.extend_from_slice(&data[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let payload = vec![0x6a; 4_000_010];
        let mut sender = FrameSender::new(&payload, 7).unwrap();
        let mut writer = Writer {
            calls: 0,
            output: Vec::new(),
        };
        assert_eq!(sender.poll(&mut writer).unwrap(), Poll::Pending);
        assert!(!sender.is_released());
        assert_eq!(sender.charged(), 4_000_015);
        assert_eq!(writer.output.len(), 4_000_003);
        assert_eq!(sender.poll(&mut writer).unwrap(), Poll::Complete);
        assert_eq!(sender.charged(), 4_000_015);
        assert_eq!(&writer.output[..5], &[0, 0x3d, 0x09, 0x0a, 7]);
        assert_eq!(&writer.output[5..], payload);
        assert!(sender.is_released());
    }
}
