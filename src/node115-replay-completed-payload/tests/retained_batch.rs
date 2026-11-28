use node115_replay_completed_payload::retained_batch::{
    Continuity, ContinuityError, RetainedRow, check_continuity,
};

fn rows() -> [RetainedRow; 3] {
    [
        RetainedRow {
            identity: 90,
            successor: 103,
            observed_predecessor: None,
            block_fingerprint: Some([0x42; 32]),
        },
        RetainedRow {
            identity: 103,
            successor: 104,
            observed_predecessor: Some([0x42; 32]),
            block_fingerprint: Some([0x51; 32]),
        },
        RetainedRow {
            identity: 104,
            successor: 105,
            observed_predecessor: Some([0x51; 32]),
            block_fingerprint: Some([0x63; 32]),
        },
    ]
}

#[test]
fn a_batch_advances_to_each_supplied_successor() {
    assert_eq!(
        check_continuity(90, &rows()),
        Ok(Continuity {
            checked_rows: 3,
            next_identity: 105,
            next_predecessor: Some([0x63; 32]),
        }),
    );
    assert_eq!(
        check_continuity(90, &[]),
        Ok(Continuity {
            checked_rows: 0,
            next_identity: 90,
            next_predecessor: None,
        }),
    );
}

#[test]
fn middle_rows_require_same_kind_reference_and_local_observation() {
    let mut chain = rows();
    chain[0].block_fingerprint = None;
    assert_eq!(
        check_continuity(90, &chain),
        Err(ContinuityError::MissingBlockFingerprint { row: 0 }),
    );
    let mut chain = rows();
    chain[1].observed_predecessor = None;
    assert_eq!(
        check_continuity(90, &chain),
        Err(ContinuityError::MissingObservedPredecessor { row: 1 }),
    );
    let mut chain = rows();
    chain[2].block_fingerprint = None;
    assert_eq!(check_continuity(90, &chain).unwrap().next_predecessor, None);
}

#[test]
fn each_reference_half_is_compared_and_identity_is_checked_first() {
    for position in [0, 31] {
        let mut observed = [0x42; 32];
        observed[position] = 0x6c;
        let mut chain = rows();
        chain[1].observed_predecessor = Some(observed);
        assert_eq!(
            check_continuity(90, &chain),
            Err(ContinuityError::Predecessor {
                row: 1,
                expected: [0x42; 32],
                observed,
            }),
        );
        chain[1].identity = 104;
        assert_eq!(
            check_continuity(90, &chain),
            Err(ContinuityError::Identity {
                row: 1,
                expected: 103,
                observed: 104,
            }),
        );
    }
}
