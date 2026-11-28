use std::collections::{BTreeMap, BTreeSet};

use node115_abci::digest_reference_handoff::{HeightEntry, ReferenceRow};
use node115_abci::hash_signature_tracker::{HashSignatureTracker, TimedDrainError};

#[test]
fn timed_drain_uses_snapshot_budget_and_independently_delivers_primary_rows() {
    const SECOND: u64 = 1_000_000_000;
    const START_HEIGHT: u64 = 75_000;
    const END_HEIGHT: u64 = START_HEIGHT + 1_001;
    let now = 200 * SECOND;
    let mut timestamps = (START_HEIGHT..=END_HEIGHT)
        .map(|height| (height, now))
        .collect::<BTreeMap<_, _>>();
    for height in START_HEIGHT..START_HEIGHT + 3 {
        timestamps.insert(height, now - 60 * SECOND);
    }
    timestamps.insert(END_HEIGHT, now - 120 * SECOND);

    let mut tracker = HashSignatureTracker::new();
    tracker.pending_heights.extend(START_HEIGHT..=END_HEIGHT);
    let digest = [0x11; 32];
    let member = [0x21; 32];
    let address = [0x31; 20];
    tracker.handoff.heights.insert(
        END_HEIGHT,
        HeightEntry {
            selected: Some(digest),
            candidates: BTreeMap::from([(digest, BTreeSet::from([member]))]),
        },
    );
    let registry = BTreeMap::from([(1, BTreeMap::from([(member, address)]))]);

    let saved = timestamps.remove(&END_HEIGHT).unwrap();
    assert_eq!(
        tracker.drain_timed(&timestamps, 120.0, now, &registry, 1),
        Err(TimedDrainError::MissingTimestamp { height: END_HEIGHT }),
    );
    assert_eq!(tracker.pending_heights.len(), 1_002);
    assert!(tracker.handoff.ready.is_empty());
    timestamps.insert(END_HEIGHT, saved);

    let (rows, lines) = tracker
        .drain_timed(&timestamps, 120.0, now, &registry, 1)
        .unwrap();
    assert_eq!(
        rows,
        [ReferenceRow {
            height: END_HEIGHT,
            digest,
            members: BTreeSet::from([address])
        }],
    );
    assert_eq!(lines.len(), 1);
    assert_eq!(tracker.pending_heights.len(), 999);
    assert!(!tracker.pending_heights.contains(&START_HEIGHT));
    assert!(!tracker.pending_heights.contains(&(START_HEIGHT + 1)));
    assert!(tracker.pending_heights.contains(&(START_HEIGHT + 2)));
    assert!(!tracker.pending_heights.contains(&END_HEIGHT));
}
