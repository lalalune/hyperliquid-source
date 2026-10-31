use super::{ChargeState, Cursor, Outcome};
use std::{env, fs, string::String, vec::Vec};

#[test]
fn short_payload_consumes_only_its_marker() {
    let mut cursor = Cursor::new(&[253, 1, 2, 3]);
    assert_eq!(cursor.read(0), Outcome::Missing(5));
    assert_eq!((cursor.position(), cursor.remaining()), (1, 3));
    assert_eq!(cursor.read(0), Outcome::Value(1));
}

#[test]
fn nonminimal_payloads_and_all_nonzero_endian_bytes_are_retained() {
    for endian in [1, 255] {
        assert_eq!(Cursor::new(&[251, 0, 1]).read(endian), Outcome::Value(1));
    }
    assert_eq!(Cursor::new(&[251, 0, 1]).read(0), Outcome::Value(256));
    assert_eq!(
        Cursor::new(&[253, 0, 0, 0, 0, 0, 0, 0, 0]).read(0),
        Outcome::Value(0)
    );
}

#[test]
fn wrapper_invalid_marker_consumption_changes_at_nine_bytes() {
    for marker in [254, 255] {
        for length in [8, 9] {
            let mut bytes = [0; 9];
            bytes[0] = marker;
            let mut cursor = Cursor::new(&bytes[..length]);
            let mut state = ChargeState {
                selector: 0,
                limit: 0,
                charged: 0,
            };
            assert_eq!(
                cursor.read_charged(&mut state),
                if marker == 254 {
                    Outcome::Tag254
                } else {
                    Outcome::Tag255
                }
            );
            assert_eq!(cursor.position(), if length == 8 { 1 } else { 0 });
        }
    }
}

#[test]
fn overflow_precedes_charge_and_limit_failure_follows_charge() {
    let mut cursor = Cursor::new(&[7]);
    let mut state = ChargeState {
        selector: 1,
        limit: u64::MAX,
        charged: u64::MAX - 7,
    };
    assert_eq!(cursor.read_charged(&mut state), Outcome::Charge);
    assert_eq!(state.charged, u64::MAX - 7);
    assert_eq!(cursor.position(), 0);
    state.charged = 0;
    state.limit = 7;
    assert_eq!(cursor.read_charged(&mut state), Outcome::Charge);
    assert_eq!(state.charged, 8);
    assert_eq!(cursor.position(), 0);
}

#[test]
fn raw_selector_two_bypasses_gate_and_wrapper_stays_little_endian() {
    let mut cursor = Cursor::new(&[251, 0x12, 0x34]);
    let mut state = ChargeState {
        selector: 2,
        limit: 0,
        charged: u64::MAX,
    };
    assert_eq!(cursor.read_charged(&mut state), Outcome::Value(0x3412));
    assert_eq!(state.charged, u64::MAX);
}

#[test]
fn inactive_output_bytes_survive_reuse() {
    let mut output = [0xa5; 24];
    Outcome::Value(u64::MAX).write_observed(&mut output);
    let old = output;
    Outcome::Tag255.write_observed(&mut output);
    assert_eq!(&output[..3], &[3, 5, 12]);
    assert_eq!(&output[3..], &old[3..]);
    let old = output;
    Outcome::Charge.write_observed(&mut output);
    assert_eq!(output[0], 2);
    assert_eq!(&output[1..], &old[1..]);
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            let s = std::str::from_utf8(p).unwrap();
            u8::from_str_radix(s, 16).unwrap()
        })
        .collect()
}

fn put(state: &mut [u8; 40], at: usize, value: u64) {
    state[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// The input comes from fresh evaluation of authenticated, dual-decoded target
/// instructions. This test does not generate its expected bytes from Rust.
#[test]
#[ignore = "requires fresh authenticated instruction ledger; run python3 tools/kind5_reader_rust.py"]
fn authenticated_instruction_corpus() {
    let path = env::var("NODE94_KIND5_VECTORS").expect("use tools/kind5_reader_rust.py");
    let text: String = fs::read_to_string(path).unwrap();
    let mut count = 0;
    for (line, row) in text.lines().enumerate() {
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(fields.len(), 8);
        let payload = unhex(fields[1]);
        let mut cursor = Cursor::new(&payload);
        let mut state = [0xa5; 40];
        let mut output = [0xa5; 24];
        let wrapper = fields[0] == "0x466be70";
        assert!(wrapper || fields[0] == "0x466dad0");
        let at = if wrapper { 16 } else { 0 };
        let result = if wrapper {
            let selector: u32 = fields[3].parse().unwrap();
            let limit = u64::from_str_radix(fields[4].trim_start_matches("0x"), 16).unwrap();
            let charged = u64::from_str_radix(fields[5].trim_start_matches("0x"), 16).unwrap();
            let mut charge = ChargeState {
                selector,
                limit,
                charged,
            };
            let result = cursor.read_charged(&mut charge);
            state[..4].copy_from_slice(&selector.to_le_bytes());
            put(&mut state, 8, limit);
            put(&mut state, 32, charge.charged);
            result
        } else {
            cursor.read(fields[2].parse().unwrap())
        };
        result.write_observed(&mut output);
        // Only this test adapter uses the packet's synthetic pointer base.
        put(&mut state, at, 0x30000 + cursor.position() as u64);
        put(&mut state, at + 8, cursor.remaining() as u64);
        assert_eq!(
            output.as_slice(),
            unhex(fields[6]),
            "output at fixture {line}"
        );
        assert_eq!(
            state.as_slice(),
            unhex(fields[7]),
            "state at fixture {line}"
        );
        count += 1;
    }
    assert_eq!(count, 28_992);
    std::println!("Compared {count} authenticated instruction fixtures: all 24 output and 40 state bytes match");
}
