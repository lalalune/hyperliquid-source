use node115_owned_tcp_receive::{Event, InitError, Outcome, Receiver};
use node115_tcp_frame_plan::Header;

fn receiver(len: u32, flag: u8) -> Receiver {
    Receiver::new(
        Header {
            payload_len: len,
            flag,
        },
        u64::from(len),
    )
    .unwrap()
}

#[test]
fn partial_and_pending_keep_the_same_chunk_until_complete() {
    let mut r = receiver(4_000_003, 1);
    let first = vec![0x31; 4_000_000];
    assert_eq!(r.step::<()>(Event::Bytes(&first)), Outcome::Progress);
    assert_eq!(r.outer_completed(), 4_000_000);
    assert_eq!(r.chunk_remaining(), 3);
    assert_eq!(r.step::<()>(Event::Bytes(b"xy")), Outcome::Progress);
    assert_eq!(r.outer_completed(), 4_000_000);
    assert_eq!(r.chunk_filled(), 2);
    assert_eq!(r.step::<()>(Event::Pending), Outcome::Pending);
    assert!(r.is_live());
    assert_eq!(r.chunk_filled(), 2);
    let Outcome::Complete {
        payload,
        decompress_after_read,
    } = r.step::<()>(Event::Bytes(b"z"))
    else {
        panic!("expected completion")
    };
    assert!(decompress_after_read);
    assert_eq!(&payload[..4_000_000], &first);
    assert_eq!(&payload[4_000_000..], b"xyz");
    assert!(!r.is_live());
    assert_eq!(r.step::<()>(Event::Pending), Outcome::Finished);
}

#[test]
fn eof_error_and_timeout_release_without_partial_payload() {
    let mut r = receiver(3, 0);
    assert_eq!(r.step::<()>(Event::Bytes(b"x")), Outcome::Progress);
    assert_eq!(r.step::<()>(Event::Bytes(b"")), Outcome::Eof);
    assert!(!r.is_live());
    let mut r = receiver(3, 2);
    assert_eq!(r.step::<()>(Event::Bytes(b"x")), Outcome::Progress);
    assert_eq!(r.step(Event::Error("io")), Outcome::Error("io"));
    assert!(!r.is_live());
    let mut r = receiver(3, 0);
    assert_eq!(r.step::<()>(Event::Bytes(b"y")), Outcome::Progress);
    assert_eq!(r.step::<()>(Event::Pending), Outcome::Pending);
    assert_eq!(r.step::<()>(Event::Timeout), Outcome::Timeout);
    assert!(!r.is_live());
}

#[test]
fn admission_empty_and_overlong_host_input_are_explicit() {
    assert!(matches!(
        Receiver::new(
            Header {
                payload_len: 3,
                flag: 0
            },
            2
        ),
        Err(InitError::OverLimit)
    ));
    let mut empty = receiver(0, 1);
    assert_eq!(
        empty.step::<()>(Event::Pending),
        Outcome::Complete {
            payload: vec![],
            decompress_after_read: true
        }
    );
    let mut r = receiver(2, 9);
    assert_eq!(
        r.step::<()>(Event::Bytes(b"abc")),
        Outcome::InvalidHostInput
    );
    assert!(!r.is_live());
    let mut r = receiver(2, 9);
    assert_eq!(
        r.step::<()>(Event::Bytes(b"ab")),
        Outcome::Complete {
            payload: b"ab".to_vec(),
            decompress_after_read: false
        }
    );
}

#[test]
fn partial_first_chunk_survives_pending_and_timeout_requires_pending() {
    let mut r = receiver(5, 0);
    assert_eq!(r.step::<()>(Event::Bytes(b"ab")), Outcome::Progress);
    assert_eq!(r.outer_completed(), 0);
    assert_eq!(r.chunk_filled(), 2);
    assert_eq!(r.step::<()>(Event::Pending), Outcome::Pending);
    assert_eq!(r.step::<()>(Event::Bytes(b"c")), Outcome::Progress);
    assert_eq!(r.chunk_filled(), 3);
    assert_eq!(
        r.step::<()>(Event::Bytes(b"de")),
        Outcome::Complete {
            payload: b"abcde".to_vec(),
            decompress_after_read: false
        }
    );
    let mut r = receiver(1, 0);
    assert_eq!(r.step::<()>(Event::Timeout), Outcome::InvalidHostInput);
}
