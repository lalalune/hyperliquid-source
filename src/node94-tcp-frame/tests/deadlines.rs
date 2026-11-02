#![cfg(feature = "timed-stream")]

use std::cell::Cell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use node94_tcp_frame::deadlines::{self, DeadlineError, Phase};
use node94_tcp_frame::stream::StreamError;
use node94_tcp_frame::{DecodeError, FrameLimits, LengthError};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, advance};

fn run(test: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap()
        .block_on(test);
}

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

struct GateIo {
    open: Rc<Cell<bool>>,
    input: Vec<u8>,
    position: usize,
    output: Vec<u8>,
    stop_after: Option<usize>,
    error: Option<io::ErrorKind>,
    zero_write: bool,
}

impl GateIo {
    fn new(input: &[u8], open: bool) -> Self {
        Self {
            open: Rc::new(Cell::new(open)),
            input: input.to_vec(),
            position: 0,
            output: Vec::new(),
            stop_after: None,
            error: None,
            zero_write: false,
        }
    }
}

impl AsyncRead for GateIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.open.get() {
            return Poll::Pending;
        }
        if let Some(kind) = self.error {
            return Poll::Ready(Err(kind.into()));
        }
        let until_stop = self.stop_after.map_or(usize::MAX, |n| n - self.position);
        let n = buf
            .remaining()
            .min(self.input.len() - self.position)
            .min(until_stop);
        buf.put_slice(&self.input[self.position..self.position + n]);
        self.position += n;
        if self.stop_after == Some(self.position) {
            self.open.set(false);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for GateIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.open.get() {
            return Poll::Pending;
        }
        if let Some(kind) = self.error {
            return Poll::Ready(Err(kind.into()));
        }
        if self.zero_write {
            return Poll::Ready(Ok(0));
        }
        let until_stop = self
            .stop_after
            .map_or(usize::MAX, |n| n - self.output.len());
        let n = buf.len().min(until_stop);
        self.output.extend_from_slice(&buf[..n]);
        if self.stop_after == Some(self.output.len()) {
            self.open.set(false);
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("frame writes must not flush implicitly")
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("frame writes must not close implicitly")
    }
}

fn expect_timeout<T: std::fmt::Debug>(
    value: Poll<Result<T, DeadlineError>>,
    phase: Phase,
    seconds: u64,
) {
    match value {
        Poll::Ready(Err(DeadlineError::Elapsed {
            phase: actual,
            limit,
        })) => {
            assert_eq!(actual, phase);
            assert_eq!(limit, Duration::from_secs(seconds));
        }
        other => panic!("expected deadline error, got {other:?}"),
    }
}

#[test]
fn header_deadline_is_forty_seconds() {
    run(async {
        let mut io = GateIo::new(&[0; 5], false);
        let mut future = Box::pin(deadlines::read_frame(&mut io, FrameLimits::new(0), true));
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(39)).await;
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(1)).await;
        expect_timeout(poll(future.as_mut()), Phase::Header, 40);
    });
}

#[test]
fn disabling_header_deadline_does_not_disable_payload_deadlines() {
    run(async {
        let mut io = GateIo::new(&[0, 0, 0, 1, 0, b'a'], false);
        io.stop_after = Some(5);
        let open = io.open.clone();
        let mut future = Box::pin(deadlines::read_frame(&mut io, FrameLimits::new(1), false));
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(400)).await;
        assert!(poll(future.as_mut()).is_pending());
        open.set(true);
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(19)).await;
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(1)).await;
        expect_timeout(
            poll(future.as_mut()),
            Phase::Payload { offset: 0, len: 1 },
            20,
        );
    });
}

#[test]
fn completed_header_beats_elapsed_timer_on_the_same_poll() {
    run(async {
        let mut io = GateIo::new(&[0; 5], false);
        let open = io.open.clone();
        let mut future = Box::pin(deadlines::read_frame(&mut io, FrameLimits::new(0), true));
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(40)).await;
        open.set(true);
        assert!(
            matches!(poll(future.as_mut()), Poll::Ready(Ok(frame)) if frame.payload.is_empty())
        );
    });
}

#[test]
fn io_error_beats_elapsed_header_timer_on_the_same_poll() {
    run(async {
        let mut io = GateIo::new(&[], false);
        io.error = Some(io::ErrorKind::ConnectionReset);
        let open = io.open.clone();
        let mut future = Box::pin(deadlines::read_frame(&mut io, FrameLimits::new(0), true));
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(40)).await;
        open.set(true);
        assert!(
            matches!(poll(future.as_mut()), Poll::Ready(Err(DeadlineError::Stream(StreamError::Io(e))))
            if e.kind() == io::ErrorKind::ConnectionReset)
        );
    });
}

#[test]
fn partial_header_does_not_reset_its_deadline() {
    run(async {
        let mut io = GateIo::new(&[0; 5], true);
        io.stop_after = Some(1);
        let mut future = Box::pin(deadlines::read_frame(&mut io, FrameLimits::new(0), true));
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(40)).await;
        expect_timeout(poll(future.as_mut()), Phase::Header, 40);
        drop(future);
        assert_eq!(io.position, 1);
    });
}

#[test]
fn writer_default_and_override_are_per_chunk() {
    run(async {
        for (setting, seconds) in [(None, 20), (Some(Duration::from_secs(60)), 60)] {
            let mut io = GateIo::new(&[], false);
            let mut future = Box::pin(deadlines::write_frame(&mut io, b"abc", 3998, setting));
            assert!(poll(future.as_mut()).is_pending());
            advance(Duration::from_secs(seconds - 1)).await;
            assert!(poll(future.as_mut()).is_pending());
            advance(Duration::from_secs(1)).await;
            expect_timeout(
                poll(future.as_mut()),
                Phase::Write { offset: 0, len: 8 },
                seconds,
            );
        }
    });
}

#[test]
fn ready_write_and_zero_write_beat_elapsed_timer() {
    run(async {
        for zero in [false, true] {
            let mut io = GateIo::new(&[], false);
            io.zero_write = zero;
            let open = io.open.clone();
            let mut future = Box::pin(deadlines::write_frame(&mut io, b"abc", 3998, None));
            assert!(poll(future.as_mut()).is_pending());
            advance(Duration::from_secs(20)).await;
            open.set(true);
            let result = poll(future.as_mut());
            if zero {
                assert!(
                    matches!(result, Poll::Ready(Err(DeadlineError::Stream(StreamError::Io(e))))
                    if e.kind() == io::ErrorKind::WriteZero)
                );
            } else {
                assert!(matches!(result, Poll::Ready(Ok(()))));
            }
        }
    });
}

#[test]
fn partial_writes_share_one_deadline_and_are_not_rolled_back() {
    run(async {
        let mut io = GateIo::new(&[], true);
        io.stop_after = Some(1);
        let mut future = Box::pin(deadlines::write_frame(&mut io, b"abc", 3998, None));
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(20)).await;
        expect_timeout(
            poll(future.as_mut()),
            Phase::Write { offset: 0, len: 8 },
            20,
        );
        drop(future);
        assert_eq!(io.output, [0]);
    });
}

struct SlowChunks {
    input: Vec<u8>,
    position: usize,
    output: Vec<u8>,
    sleep: Option<Pin<Box<Sleep>>>,
    header_delay: bool,
}

impl SlowChunks {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            position: 0,
            output: Vec::new(),
            sleep: None,
            header_delay: false,
        }
    }

    fn delay(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let sleep = self.sleep.get_or_insert_with(|| {
            Box::pin(tokio::time::sleep(Duration::from_secs(
                if self.header_delay && self.position == 0 {
                    39
                } else {
                    19
                },
            )))
        });
        match sleep.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                self.sleep = None;
                Poll::Ready(())
            }
        }
    }
}

impl AsyncRead for SlowChunks {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if (self.position >= 5 || self.header_delay) && self.delay(cx).is_pending() {
            return Poll::Pending;
        }
        let n = buf.remaining().min(self.input.len() - self.position);
        buf.put_slice(&self.input[self.position..self.position + n]);
        self.position += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SlowChunks {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.delay(cx).is_pending() {
            return Poll::Pending;
        }
        self.output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("unexpected flush")
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("unexpected close")
    }
}

#[test]
fn each_payload_chunk_gets_a_fresh_twenty_seconds() {
    run(async {
        let len = 4_000_001u32;
        let mut wire = len.to_be_bytes().to_vec();
        wire.push(0);
        wire.resize(5 + len as usize, 0x5a);
        let mut io = SlowChunks::new(wire);
        let start = Instant::now();
        let mut future = Box::pin(deadlines::read_frame(
            &mut io,
            FrameLimits::new(u64::from(len)),
            true,
        ));
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(19)).await;
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(1)).await;
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(18)).await;
        assert!(
            matches!(poll(future.as_mut()), Poll::Ready(Ok(frame)) if frame.payload.len() == len as usize)
        );
        assert_eq!(Instant::now() - start, Duration::from_secs(38));
    });
}

#[test]
fn each_write_chunk_gets_a_fresh_twenty_seconds() {
    run(async {
        let payload = vec![0x5a; 4_000_001];
        let mut io = SlowChunks::new(Vec::new());
        let mut future = Box::pin(deadlines::write_frame(&mut io, &payload, 3998, None));
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(19)).await;
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(1)).await;
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(18)).await;
        assert!(matches!(poll(future.as_mut()), Poll::Ready(Ok(()))));
        drop(future);
        assert_eq!(io.output.len(), payload.len() + 5);
        assert_eq!(&io.output[..5], &[0, 0x3d, 9, 1, 0]);
    });
}

#[test]
fn length_rejection_precedes_payload_io_or_deadline() {
    run(async {
        let mut io = GateIo::new(&[0, 0, 0, 5, 0], true);
        let result = deadlines::read_frame(&mut io, FrameLimits::new(4), true).await;
        assert!(matches!(
            result,
            Err(DeadlineError::Stream(StreamError::Decode(
                DecodeError::Length(LengthError::FrameTooLarge {
                    declared: 5,
                    max: 4
                })
            )))
        ));
        assert_eq!(io.position, 5);
    });
}

#[test]
fn header_deadline_does_not_cover_later_payload_io() {
    run(async {
        let mut io = SlowChunks::new(vec![0, 0, 0, 1, 0, b'x']);
        io.header_delay = true;
        let start = Instant::now();
        let mut future = Box::pin(deadlines::read_frame(&mut io, FrameLimits::new(1), true));
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(39)).await;
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(1)).await;
        assert!(poll(future.as_mut()).is_pending());
        advance(Duration::from_secs(18)).await;
        assert!(matches!(poll(future.as_mut()), Poll::Ready(Ok(frame)) if frame.payload == b"x"));
        assert_eq!(Instant::now() - start, Duration::from_secs(58));
    });
}
