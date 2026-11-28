use node115_replay_completed_payload::{CompletedPayload, decode_completed_payload};

fn decoded_archive_clock(seconds: &[u8], nanos: &[u8]) -> String {
    let mut wire = vec![0; 10]; // Block tag and signature placeholder
    wire.extend([0x42; 20]); // proposer
    wire.push(0); // empty header digest vector
    wire.extend(seconds);
    wire.extend(nanos);
    wire.extend([0, 1, 2, 3, 4, 5]); // quorum parent and its five words
    wire.extend([0x31; 32]); // quorum hash
    wire.extend([0, 0, 0]); // votes, proof option, attachment option
    let decoded = decode_completed_payload(CompletedPayload::Plain(&wire)).unwrap();
    assert_eq!(decoded.consumed, wire.len());
    decoded.render_replica_time().unwrap().as_str().to_owned()
}

#[test]
fn decoded_clock_preserves_native_zero_three_six_and_nine_fraction_widths() {
    for (nanos, expected) in [
        (0u32, "1970-01-01T00:00:00"),
        (120_000_000, "1970-01-01T00:00:00.120"),
        (120_123_000, "1970-01-01T00:00:00.120123"),
        (120_123_456, "1970-01-01T00:00:00.120123456"),
    ] {
        if nanos == 0 {
            assert_eq!(decoded_archive_clock(&[0], &[0]), expected);
        } else {
            let mut encoded = vec![252];
            encoded.extend(nanos.to_le_bytes());
            assert_eq!(decoded_archive_clock(&[0], &encoded), expected);
        }
    }
}

#[test]
fn decoded_clock_preserves_pre_epoch_dates_and_the_leap_second_arm() {
    assert_eq!(
        decoded_archive_clock(&[1], &[9]), // ZigZag(-1).
        "1969-12-31T23:59:59.000000009"
    );
    let seconds = [252, 254, 140, 208, 176]; // ZigZag(1483228799).
    let mut nanos = vec![252];
    nanos.extend(1_123_000_000u32.to_le_bytes());
    assert_eq!(
        decoded_archive_clock(&seconds, &nanos),
        "2016-12-31T23:59:60.123"
    );
}

#[test]
fn opaque_tx_has_no_replica_clock() {
    let decoded = decode_completed_payload(CompletedPayload::Plain(&[1, 0])).unwrap();
    assert!(decoded.render_replica_time().is_none());
}
