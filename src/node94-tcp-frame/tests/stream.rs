#![cfg(feature = "stream")]

use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use node94_tcp_frame::stream::{StreamError, read_frame, write_frame};
use node94_tcp_frame::{DecodeError, FrameLimits, LengthError};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct Trace {
    requests: Vec<usize>,
    transferred: usize,
    flushes: usize,
    shutdowns: usize,
}

struct Reader {
    bytes: Vec<u8>,
    pos: usize,
    maximum: usize,
    alternate_pending: bool,
    polls: usize,
    fail_at: Option<(usize, io::ErrorKind)>,
    trace: Rc<RefCell<Trace>>,
}

impl Reader {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            pos: 0,
            maximum: usize::MAX,
            alternate_pending: false,
            polls: 0,
            fail_at: None,
            trace: Rc::default(),
        }
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.polls += 1;
        if self.alternate_pending && self.polls % 2 == 1 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.trace.borrow_mut().requests.push(buf.remaining());
        if let Some((offset, kind)) = self.fail_at
            && self.pos >= offset
        {
            return Poll::Ready(Err(kind.into()));
        }
        let until_error = self.fail_at.map_or(usize::MAX, |(n, _)| n - self.pos);
        let n = buf
            .remaining()
            .min(self.maximum)
            .min(self.bytes.len() - self.pos)
            .min(until_error);
        buf.put_slice(&self.bytes[self.pos..self.pos + n]);
        self.pos += n;
        self.trace.borrow_mut().transferred += n;
        Poll::Ready(Ok(()))
    }
}

struct Writer {
    bytes: Vec<u8>,
    maximum: usize,
    alternate_pending: bool,
    polls: usize,
    fail_at: Option<(usize, io::ErrorKind)>,
    zero_at: Option<usize>,
    trace: Rc<RefCell<Trace>>,
}

impl Writer {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            maximum: usize::MAX,
            alternate_pending: false,
            polls: 0,
            fail_at: None,
            zero_at: None,
            trace: Rc::default(),
        }
    }
}

impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.polls += 1;
        if self.alternate_pending && self.polls % 2 == 1 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.trace.borrow_mut().requests.push(buf.len());
        if let Some((offset, kind)) = self.fail_at
            && self.bytes.len() >= offset
        {
            return Poll::Ready(Err(kind.into()));
        }
        if self.zero_at.is_some_and(|n| self.bytes.len() >= n) {
            return Poll::Ready(Ok(0));
        }
        let until_error = self
            .fail_at
            .map_or(usize::MAX, |(n, _)| n - self.bytes.len());
        let until_zero = self.zero_at.map_or(usize::MAX, |n| n - self.bytes.len());
        let n = buf.len().min(self.maximum).min(until_error).min(until_zero);
        self.bytes.extend_from_slice(&buf[..n]);
        self.trace.borrow_mut().transferred += n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.trace.borrow_mut().flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.trace.borrow_mut().shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

fn finish<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..100_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("scripted I/O did not complete");
}

fn io_kind(error: StreamError) -> io::ErrorKind {
    match error {
        StreamError::Io(error) => error.kind(),
        other => panic!("expected I/O error, got {other:?}"),
    }
}

#[test]
fn fragmented_pending_reads_preserve_every_header_and_payload_byte() {
    let mut reader = Reader::new(vec![0, 0, 0, 3, 0, b'a', b'b', b'c', 0xff]);
    reader.maximum = 1;
    reader.alternate_pending = true;
    let frame = finish(read_frame(&mut reader, FrameLimits::new(3))).unwrap();
    assert_eq!(frame.payload, b"abc");
    assert_eq!(frame.consumed, 8);
    assert_eq!(reader.pos, 8);
    assert_eq!(reader.trace.borrow().requests, [5, 4, 3, 2, 1, 3, 2, 1]);
}

#[test]
fn each_header_or_payload_truncation_is_unexpected_eof() {
    let bytes = [0, 0, 0, 3, 0, b'a', b'b', b'c'];
    for end in 0..bytes.len() {
        let mut reader = Reader::new(bytes[..end].to_vec());
        let error = finish(read_frame(&mut reader, FrameLimits::new(3))).unwrap_err();
        assert_eq!(io_kind(error), io::ErrorKind::UnexpectedEof, "end={end}");
    }
}

#[test]
fn zero_payload_does_not_poll_for_payload_or_consume_next_header() {
    let mut reader = Reader::new(vec![0, 0, 0, 0, 0, 0xfe]);
    let frame = finish(read_frame(&mut reader, FrameLimits::new(0))).unwrap();
    assert!(frame.payload.is_empty());
    assert_eq!(frame.consumed, 5);
    assert_eq!(reader.trace.borrow().requests, [5]);
    assert_eq!(reader.pos, 5);
}

#[test]
fn over_limit_header_is_rejected_before_any_payload_read() {
    let mut reader = Reader::new(vec![0, 0, 0, 5, 0, 9, 9, 9, 9, 9]);
    reader.fail_at = Some((5, io::ErrorKind::PermissionDenied));
    let error = finish(read_frame(&mut reader, FrameLimits::new(4))).unwrap_err();
    assert!(matches!(
        error,
        StreamError::Decode(DecodeError::Length(LengthError::FrameTooLarge {
            declared: 5,
            max: 4
        }))
    ));
    assert_eq!(reader.pos, 5);
    assert_eq!(reader.trace.borrow().requests, [5]);
}

#[test]
fn all_non_one_flags_remain_raw() {
    for flag in (0..=u8::MAX).filter(|flag| *flag != 1) {
        let mut reader = Reader::new(vec![0, 0, 0, 2, flag, 0xff, 0x00]);
        let frame = finish(read_frame(&mut reader, FrameLimits::new(2))).unwrap();
        assert_eq!(frame.header.compression_flag, flag);
        assert_eq!(frame.payload, [0xff, 0x00]);
    }
}

#[test]
fn independent_literal_lz4_fixture_decodes_after_fragmented_io() {
    // BE frame length 8, flag 1, LE decoded length 3, literal-only LZ4 token.
    let mut reader = Reader::new(vec![0, 0, 0, 8, 1, 3, 0, 0, 0, 0x30, b'a', b'b', b'c']);
    reader.maximum = 2;
    reader.alternate_pending = true;
    let frame = finish(read_frame(&mut reader, FrameLimits::new(8))).unwrap();
    assert_eq!(frame.payload, b"abc");
    assert_eq!(frame.consumed, 13);
}

#[test]
fn huge_decoded_size_is_rejected_without_attempting_a_huge_output() {
    let mut reader = Reader::new(vec![0, 0, 0, 4, 1, 0xff, 0xff, 0xff, 0xff]);
    assert!(matches!(
        finish(read_frame(&mut reader, FrameLimits::new(4))),
        Err(StreamError::Decode(DecodeError::Length(
            LengthError::DecompressedTooLarge {
                uncompressed_size: u32::MAX,
                ..
            }
        )))
    ));
}

#[test]
fn concatenated_frames_are_read_individually() {
    let mut reader = Reader::new(vec![0, 0, 0, 1, 0, b'a', 0, 0, 0, 1, 2, b'b']);
    assert_eq!(
        finish(read_frame(&mut reader, FrameLimits::new(1)))
            .unwrap()
            .payload,
        b"a"
    );
    assert_eq!(reader.pos, 6);
    assert_eq!(
        finish(read_frame(&mut reader, FrameLimits::new(1)))
            .unwrap()
            .payload,
        b"b"
    );
    assert_eq!(reader.pos, 12);
}

#[test]
fn payload_chunks_exclude_the_header_and_use_decimal_four_million() {
    let size = 4_000_007_u32;
    let mut wire = size.to_be_bytes().to_vec();
    wire.push(0);
    wire.resize(5 + size as usize, 0x5a);
    let mut reader = Reader::new(wire);
    let frame = finish(read_frame(&mut reader, FrameLimits::new(u64::from(size)))).unwrap();
    assert_eq!(frame.payload.len(), size as usize);
    assert!(frame.payload.iter().all(|&byte| byte == 0x5a));
    assert_eq!(reader.trace.borrow().requests, [5, 4_000_000, 7]);
}

#[test]
fn underlying_read_errors_are_not_changed_or_retried() {
    for kind in [io::ErrorKind::Interrupted, io::ErrorKind::ConnectionReset] {
        for offset in [0, 2, 5, 6] {
            let mut reader = Reader::new(vec![0, 0, 0, 3, 0, b'a', b'b', b'c']);
            reader.fail_at = Some((offset, kind));
            let error = finish(read_frame(&mut reader, FrameLimits::new(3))).unwrap_err();
            assert_eq!(io_kind(error), kind);
            assert_eq!(reader.pos, offset);
        }
    }
}

#[test]
fn a_cancelled_read_does_not_roll_back_consumed_bytes() {
    let mut reader = Reader::new(vec![0, 0, 0, 3, 0, b'a', b'b', b'c']);
    reader.maximum = 1;
    reader.alternate_pending = true;
    let trace = reader.trace.clone();
    let mut future = Box::pin(read_frame(&mut reader, FrameLimits::new(3)));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    assert_eq!(trace.borrow().transferred, 1);
    drop(future);
    assert_eq!(reader.pos, 1);
}

#[test]
fn short_pending_writes_emit_the_hand_encoded_frame_once() {
    let mut writer = Writer::new();
    writer.maximum = 1;
    writer.alternate_pending = true;
    finish(write_frame(&mut writer, b"abc", 3998)).unwrap();
    assert_eq!(writer.bytes, [0, 0, 0, 3, 0, b'a', b'b', b'c']);
    assert_eq!(writer.trace.borrow().requests, [8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(writer.trace.borrow().flushes, 0);
    assert_eq!(writer.trace.borrow().shutdowns, 0);
}

#[test]
fn write_chunks_include_the_header() {
    let mut writer = Writer::new();
    let payload = vec![0x5a; 4_000_007];
    finish(write_frame(&mut writer, &payload, 3998)).unwrap();
    assert_eq!(&writer.bytes[..5], &[0, 0x3d, 0x09, 7, 0]);
    assert_eq!(writer.bytes.len(), payload.len() + 5);
    assert!(writer.bytes[5..] == payload[..], "payload bytes differ");
    assert_eq!(writer.trace.borrow().requests, [4_000_000, 12]);
}

#[test]
fn write_zero_and_io_errors_preserve_partial_output() {
    for offset in [0, 2, 5, 7] {
        let expected = [0, 0, 0, 3, 0, b'a', b'b', b'c'];
        let mut writer = Writer::new();
        writer.zero_at = Some(offset);
        assert_eq!(
            io_kind(finish(write_frame(&mut writer, b"abc", 3998)).unwrap_err()),
            io::ErrorKind::WriteZero
        );
        assert_eq!(writer.bytes, expected[..offset]);
        let mut writer = Writer::new();
        writer.fail_at = Some((offset, io::ErrorKind::BrokenPipe));
        assert_eq!(
            io_kind(finish(write_frame(&mut writer, b"abc", 3998)).unwrap_err()),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(writer.bytes, expected[..offset]);
    }
}

#[test]
fn empty_write_still_emits_the_five_byte_header() {
    let mut writer = Writer::new();
    finish(write_frame(&mut writer, b"", 4001)).unwrap();
    assert_eq!(writer.bytes, [0, 0, 0, 0, 0]);
    assert_eq!(writer.trace.borrow().requests, [5]);
}

#[test]
fn caller_owned_trait_objects_work_without_a_runtime_or_socket() {
    let mut reader = Reader::new(vec![0, 0, 0, 1, 0, b'x']);
    let input: &mut (dyn AsyncRead + Unpin) = &mut reader;
    assert_eq!(
        finish(read_frame(input, FrameLimits::new(1)))
            .unwrap()
            .payload,
        b"x"
    );
    let mut writer = Writer::new();
    let output: &mut (dyn AsyncWrite + Unpin) = &mut writer;
    finish(write_frame(output, b"y", 3999)).unwrap();
    assert_eq!(writer.bytes, [0, 0, 0, 1, 0, b'y']);
}
