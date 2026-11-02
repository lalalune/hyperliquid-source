use node94_consensus_admission::request_throttle::{
    InitialStateError, RequestKey, RequestRow, RequestThrottle, RequestTimestamp, ThrottleOutcome,
};
use std::collections::BTreeSet;

fn time(second: u32, nano: u32) -> RequestTimestamp {
    RequestTimestamp {
        packed_date: 16_580_630,
        second,
        nano,
    }
}

fn key(round: u64, last: u8) -> RequestKey {
    let mut hash = [0; 32];
    hash[31] = last;
    RequestKey { round, hash }
}

#[test]
fn retained_stamp_inclusive_deadline_and_reasons_after_sent() {
    let mut state = RequestThrottle::new();
    let k = key(5, 7);
    assert_eq!(
        state.consider(k, time(0, 0), 0, None),
        ThrottleOutcome::Held {
            registered: true,
            deadline: time(1, 0)
        }
    );
    assert_eq!(
        state.consider(k, time(0, 999_999_999), 1, None),
        ThrottleOutcome::Held {
            registered: false,
            deadline: time(1, 0)
        }
    );
    assert_eq!(
        state.consider(k, time(1, 0), 2, None),
        ThrottleOutcome::Request {
            registered: false,
            deadline: time(1, 0),
            key: k
        }
    );
    assert!(matches!(
        state.consider(k, time(2, 0), 255, None),
        ThrottleOutcome::Held { .. }
    ));
    let rows = state.snapshot();
    assert_eq!(rows[0].stamp, time(0, 0));
    assert_eq!(rows[0].reasons, BTreeSet::from([0, 1, 2, 255]));
    assert!(rows[0].sent);
}

#[test]
fn whole_unsigned_round_and_hash_participate_in_identity() {
    let mut state = RequestThrottle::new();
    for k in [key(u64::MAX, 0), key(0, 1), key(0, 0)] {
        assert!(matches!(
            state.consider(k, time(0, 0), 1, Some(0)),
            ThrottleOutcome::Request {
                registered: true,
                ..
            }
        ));
    }
    assert_eq!(
        state.snapshot().iter().map(|r| r.key).collect::<Vec<_>>(),
        vec![key(0, 0), key(0, 1), key(u64::MAX, 0)]
    );
}

#[test]
fn finite_map_and_all_reason_bytes_preserve_prior_rows() {
    let mut state = RequestThrottle::new();
    for i in (0..131).rev() {
        state.consider(key(i, 0), time(0, 0), 0, None);
    }
    for reason in 0..=255 {
        state.consider(key(65, 0), time(0, 0), reason, None);
    }
    let rows = state.snapshot();
    assert_eq!(rows.len(), 131);
    assert_eq!(rows[65].reasons.len(), 256);
    assert!(rows.iter().all(|r| r.stamp == time(0, 0) && !r.sent));
    assert!(rows
        .iter()
        .enumerate()
        .all(|(i, r)| r.key.round == i as u64));
}

#[test]
fn invalid_time_precedes_any_state_mutation() {
    let mut state = RequestThrottle::new();
    state.consider(key(1, 1), time(0, 0), 1, None);
    let before = state.clone();
    for bad in [
        RequestTimestamp {
            packed_date: 0,
            second: 0,
            nano: 0,
        },
        time(86_400, 0),
        time(0, 1_000_000_000),
        RequestTimestamp {
            packed_date: 16_580_631,
            second: 0,
            nano: 0,
        },
    ] {
        assert_eq!(
            state.consider(key(2, 2), bad, 2, Some(0)),
            ThrottleOutcome::InvalidTime
        );
        assert_eq!(state, before);
    }
}

#[test]
fn deadline_range_keeps_registration_and_reason_even_when_sent() {
    // Last canonical day: year262142 is common; its canonical low nibble is14.
    let end = RequestTimestamp {
        packed_date: (262_142 << 13) | (365 << 4) | 14,
        second: 86_399,
        nano: 999_999_999,
    };
    assert!(end.is_valid());
    let k = key(0, 0);
    let mut state = RequestThrottle::new();
    assert_eq!(
        state.consider(k, end, 1, None),
        ThrottleOutcome::DeadlineRange { registered: true }
    );
    assert_eq!(state.snapshot()[0].reasons, BTreeSet::from([1]));
    assert!(!state.snapshot()[0].sent);
    assert!(matches!(
        state.consider(k, end, 2, Some(0)),
        ThrottleOutcome::Request { .. }
    ));
    assert_eq!(
        state.consider(k, end, 3, None),
        ThrottleOutcome::DeadlineRange { registered: false }
    );
    assert!(state.snapshot()[0].sent);
    assert_eq!(state.snapshot()[0].reasons, BTreeSet::from([1, 2, 3]));
}

#[test]
fn supplied_state_and_snapshot_ownership_are_explicit() {
    let row = RequestRow {
        key: key(2, 3),
        stamp: time(4, 5),
        reasons: BTreeSet::from([4, 9]),
        sent: true,
    };
    assert_eq!(
        RequestThrottle::from_rows([row.clone(), row.clone()]),
        Err(InitialStateError::DuplicateKey)
    );
    let mut invalid = row.clone();
    invalid.stamp.nano = u32::MAX;
    assert_eq!(
        RequestThrottle::from_rows([invalid]),
        Err(InitialStateError::InvalidTime)
    );
    let state = RequestThrottle::from_rows([row.clone()]).unwrap();
    let mut snapshot = state.snapshot();
    snapshot[0].reasons.clear();
    snapshot[0].sent = false;
    assert_eq!(state.snapshot(), vec![row]);
}

#[test]
fn zero_negative_and_nonfinite_product_delays_admit_immediately() {
    for bits in [
        0,
        0x8000_0000_0000_0000,
        0xbff0_0000_0000_0000,
        0x7ff0_0000_0000_0000,
        0x7ff0_0000_0000_0001,
        0x7fef_ffff_ffff_ffff,
    ] {
        let mut state = RequestThrottle::new();
        assert!(matches!(
            state.consider(key(1, 1), time(10, 0), 3, Some(bits)),
            ThrottleOutcome::Request {
                registered: true,
                ..
            }
        ));
    }
}

#[test]
fn explicit_vote_delay_and_backward_event_time_keep_original_stamp() {
    let mut state = RequestThrottle::new();
    let k = key(8, 4);
    let bits = Some(0x3fc3_3333_3333_3333);
    let deadline = time(2, 150_000_000);
    assert_eq!(
        state.consider(k, time(2, 0), 3, bits),
        ThrottleOutcome::Held {
            registered: true,
            deadline
        }
    );
    assert_eq!(
        state.consider(k, time(1, 0), 4, bits),
        ThrottleOutcome::Held {
            registered: false,
            deadline
        }
    );
    assert_eq!(
        state.consider(k, deadline, 5, bits),
        ThrottleOutcome::Request {
            registered: false,
            deadline,
            key: k
        }
    );
    assert_eq!(state.snapshot()[0].stamp, time(2, 0));
}
