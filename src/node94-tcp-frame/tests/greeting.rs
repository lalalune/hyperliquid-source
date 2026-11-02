#![cfg(feature = "timed-stream")]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use node94_tcp_frame::deadlines::{DeadlineError, Phase};
use node94_tcp_frame::greeting::{self, ExchangeError, Request};
use node94_tcp_frame::stream::StreamError;
use node94_tcp_frame::{DecodeError, LengthError};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

fn run(future: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap()
        .block_on(future);
}

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

struct Stream {
    input: Vec<u8>,
    position: usize,
    output: Vec<u8>,
    stop_write_at: usize,
    stop_read_at: usize,
    write_error: Option<io::ErrorKind>,
    read_error: Option<io::ErrorKind>,
    read_polls: usize,
    zero_write: bool,
}

impl Stream {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            position: 0,
            output: Vec::new(),
            stop_write_at: usize::MAX,
            stop_read_at: usize::MAX,
            write_error: None,
            read_error: None,
            read_polls: 0,
            zero_write: false,
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.read_polls += 1;
        assert_eq!(
            self.output.len(),
            8,
            "reply read before full greeting write"
        );
        if self.position == self.stop_read_at {
            return Poll::Pending;
        }
        if let Some(error) = self.read_error {
            return Poll::Ready(Err(error.into()));
        }
        let count = buf
            .remaining()
            .min(2)
            .min(self.input.len() - self.position)
            .min(self.stop_read_at - self.position);
        buf.put_slice(&self.input[self.position..self.position + count]);
        self.position += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.output.len() == self.stop_write_at {
            return Poll::Pending;
        }
        if let Some(error) = self.write_error {
            return Poll::Ready(Err(error.into()));
        }
        if self.zero_write {
            return Poll::Ready(Ok(0));
        }
        let count = buf.len().min(2).min(self.stop_write_at - self.output.len());
        self.output.extend_from_slice(&buf[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("greeting must not flush the stream")
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("greeting must not close the stream")
    }
}

fn request(first: u8, second: u8, time_header: bool) -> Request {
    Request {
        first,
        second,
        time_header,
    }
}

fn raw_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.push(0);
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn all_source_byte_pairs_are_preserved_and_limit_depends_only_on_first() {
    for first in 0..=u8::MAX {
        for second in 0..=u8::MAX {
            for time_header in [false, true] {
                let req = request(first, second, time_header);
                assert_eq!(req.payload(), [first, second, 0]);
                assert_eq!(
                    req.reply_limits().max_len(),
                    if first == 0 { 1_000 } else { 3_000_000_000 }
                );
            }
        }
    }
}

#[test]
fn fragmented_exchange_writes_exact_request_and_preserves_raw_reply_and_next_frame() {
    run(async {
        for req in [
            request(0, 255, false),
            request(1, 0, false),
            request(255, 128, true),
        ] {
            let mut input = raw_frame(&[0, 255, 1, 2, 3]);
            input.extend_from_slice(&raw_frame(&[5]));
            let mut io = Stream::new(input);
            let frame = greeting::exchange_frame(&mut io, req).await.unwrap();
            assert_eq!(io.output, [0, 0, 0, 3, 0, req.first, req.second, 0]);
            assert_eq!(frame.payload, [0, 255, 1, 2, 3]);
            assert_eq!(io.position, 10);
            assert_eq!(&io.input[io.position..], raw_frame(&[5]));
        }
    });
}

#[test]
fn compressed_reply_uses_the_existing_decoder() {
    run(async {
        let mut io = Stream::new(vec![0, 0, 0, 8, 1, 3, 0, 0, 0, 0x30, b'a', b'b', b'c']);
        let frame = greeting::exchange_frame(&mut io, request(0, 2, true))
            .await
            .unwrap();
        assert_eq!(frame.payload, b"abc");
        assert_eq!(frame.consumed, 13);
        assert!(frame.header.is_compressed());
    });
}

#[test]
fn exactly_one_thousand_reply_bytes_are_admitted() {
    run(async {
        let payload = vec![0x5a; 1_000];
        let mut io = Stream::new(raw_frame(&payload));
        assert_eq!(
            greeting::exchange_frame(&mut io, request(0, 255, true))
                .await
                .unwrap()
                .payload,
            payload
        );
    });
}

#[test]
fn both_selected_limits_reject_before_reading_or_allocating_payload() {
    run(async {
        for (first, declared, max) in [
            (0, 1_001u32, 1_000u64),
            (128, 3_000_000_001u32, 3_000_000_000u64),
        ] {
            let mut input = declared.to_be_bytes().to_vec();
            input.extend_from_slice(&[0, 0x55]);
            let mut io = Stream::new(input);
            let result = greeting::exchange_frame(&mut io, request(first, 0, false)).await;
            assert!(
                matches!(result, Err(ExchangeError::Receive(DeadlineError::Stream(StreamError::Decode(DecodeError::Length(LengthError::FrameTooLarge { declared: d, max: m }))))) if d == declared && m == max)
            );
            assert_eq!(io.position, 5);
        }
    });
}

#[test]
fn selected_limit_also_rejects_forged_decompressed_size() {
    run(async {
        let mut io = Stream::new(vec![0, 0, 0, 4, 1, 0xe9, 3, 0, 0]);
        let result = greeting::exchange_frame(&mut io, request(0, 1, true)).await;
        assert!(matches!(
            result,
            Err(ExchangeError::Receive(DeadlineError::Stream(
                StreamError::Decode(DecodeError::Length(LengthError::DecompressedTooLarge {
                    uncompressed_size: 1_001,
                    max: 1_000,
                    ..
                }))
            )))
        ));
    });
}

#[test]
fn send_failure_does_not_poll_the_reader() {
    run(async {
        for zero in [false, true] {
            let mut io = Stream::new(raw_frame(&[2]));
            io.zero_write = zero;
            io.write_error = if zero {
                None
            } else {
                Some(io::ErrorKind::BrokenPipe)
            };
            let result = greeting::exchange_frame(&mut io, request(1, 0, false)).await;
            assert!(
                matches!(result, Err(ExchangeError::Send(DeadlineError::Stream(StreamError::Io(e)))) if e.kind() == if zero { io::ErrorKind::WriteZero } else { io::ErrorKind::BrokenPipe })
            );
            assert_eq!(io.read_polls, 0);
        }
    });
}

#[test]
fn receive_error_and_all_short_reply_frames_are_propagated() {
    run(async {
        let wire = raw_frame(&[1, 2, 3]);
        for end in 0..wire.len() {
            let mut io = Stream::new(wire[..end].to_vec());
            let result = greeting::exchange_frame(&mut io, request(0, 0, true)).await;
            assert!(
                matches!(result, Err(ExchangeError::Receive(DeadlineError::Stream(StreamError::Io(e)))) if e.kind() == io::ErrorKind::UnexpectedEof)
            );
        }
        let mut io = Stream::new(Vec::new());
        io.read_error = Some(io::ErrorKind::ConnectionReset);
        let result = greeting::exchange_frame(&mut io, request(0, 0, true)).await;
        assert!(
            matches!(result, Err(ExchangeError::Receive(DeadlineError::Stream(StreamError::Io(e)))) if e.kind() == io::ErrorKind::ConnectionReset)
        );
    });
}

#[test]
fn greeting_write_uses_twenty_seconds_despite_carried_sixty_in_target() {
    run(async {
        let mut io = Stream::new(raw_frame(&[2]));
        io.stop_write_at = 3;
        let mut future = Box::pin(greeting::exchange_frame(&mut io, request(0, 1, true)));
        assert!(poll(future.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(20)).await;
        assert!(
            matches!(poll(future.as_mut()), Poll::Ready(Err(ExchangeError::Send(DeadlineError::Elapsed { phase: Phase::Write { offset: 0, len: 8 }, limit }))) if limit == Duration::from_secs(20))
        );
        drop(future);
        assert_eq!(io.output.len(), 3);
        assert_eq!(io.read_polls, 0);
    });
}

#[test]
fn header_timing_is_independent_of_both_transmitted_bytes() {
    run(async {
        for (first, second, time_header) in [(0, 0, true), (1, 0, false), (0, 1, false)] {
            let mut io = Stream::new(raw_frame(&[2]));
            io.stop_read_at = 0;
            let mut future = Box::pin(greeting::exchange_frame(
                &mut io,
                request(first, second, time_header),
            ));
            assert!(poll(future.as_mut()).is_pending());
            tokio::time::advance(Duration::from_secs(40)).await;
            if time_header {
                assert!(matches!(
                    poll(future.as_mut()),
                    Poll::Ready(Err(ExchangeError::Receive(DeadlineError::Elapsed {
                        phase: Phase::Header,
                        ..
                    })))
                ));
            } else {
                assert!(poll(future.as_mut()).is_pending());
            }
        }
    });
}

#[test]
fn disabling_header_timing_still_times_the_reply_payload() {
    run(async {
        let mut io = Stream::new(raw_frame(&[2]));
        io.stop_read_at = 5;
        let mut future = Box::pin(greeting::exchange_frame(&mut io, request(1, 1, false)));
        assert!(poll(future.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(20)).await;
        assert!(matches!(
            poll(future.as_mut()),
            Poll::Ready(Err(ExchangeError::Receive(DeadlineError::Elapsed {
                phase: Phase::Payload { offset: 0, len: 1 },
                ..
            })))
        ));
    });
}

#[test]
fn cancelling_after_the_request_preserves_the_partial_exchange() {
    run(async {
        let mut io = Stream::new(raw_frame(&[2]));
        io.stop_read_at = 0;
        let mut future = Box::pin(greeting::exchange_frame(&mut io, request(255, 254, true)));
        assert!(poll(future.as_mut()).is_pending());
        drop(future);
        assert_eq!(io.output, [0, 0, 0, 3, 0, 255, 254, 0]);
        assert_eq!(io.position, 0);
    });
}
