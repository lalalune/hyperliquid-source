use node115_digest_reference_handoff::*;
use std::collections::{BTreeMap, BTreeSet};

const A: Digest = [0x11; 32];
const B: Digest = [0x22; 32];
const ID: MemberId = [0x33; 32];
const ADDRESS: Address = [0x44; 20];

fn entry(selected: Option<Digest>, ids: &[MemberId]) -> HeightEntry {
    HeightEntry {
        selected,
        candidates: [(A, ids.iter().copied().collect())].into(),
    }
}

fn registry() -> Registry {
    [(7, [(ID, ADDRESS)].into())].into()
}

fn tracker() -> TrackerProjection {
    TrackerProjection {
        heights: [(41, entry(Some(A), &[ID]))].into(),
        ready: vec![],
    }
}

fn row(height: u64, digest: Digest, nonempty: bool) -> ReferenceRow {
    ReferenceRow {
        height,
        digest,
        members: if nonempty {
            [ADDRESS].into()
        } else {
            BTreeSet::new()
        },
    }
}

// Expected outcomes below are hand-derived from the native branches listed in
// the packet's contract table, not produced by calling the implementation.

#[test]
fn selected_digest_registry_remap_and_comparator_join() {
    let mut t = tracker();
    t.extract_selected(41, &registry(), 7);
    let emitted = t.drain_ready();
    assert_eq!(emitted, vec![row(41, A, true)]);
    assert!(t.ready.is_empty());
    assert_eq!(
        compare_prefix(&emitted, &[(41, A)].into()),
        vec![Observation {
            height: 41,
            incoming: A,
            local: Some(A),
            comparison: Comparison::Equal,
        }]
    );
}

#[test]
fn absent_height_unset_selector_and_absent_selected_candidate_do_not_queue() {
    let mut t = tracker();
    t.heights.insert(42, entry(None, &[ID]));
    t.heights.insert(43, entry(Some(B), &[ID]));
    for h in [40, 42, 43] {
        t.extract_selected(h, &registry(), 7);
    }
    assert!(t.ready.is_empty());
}

#[test]
fn selector_is_not_replaced_with_an_available_candidate() {
    let mut t = tracker();
    t.heights
        .get_mut(&41)
        .unwrap()
        .candidates
        .insert(B, [ID].into());
    t.heights.get_mut(&41).unwrap().selected = Some(B);
    t.extract_selected(41, &registry(), 7);
    assert_eq!(t.drain_ready(), vec![row(41, B, true)]);
}

#[test]
fn current_registry_context_is_used_and_failures_are_filtered() {
    for r in [Registry::new(), [(7, BTreeMap::new())].into(), registry()] {
        let mut t = tracker();
        t.extract_selected(41, &r, 8);
        // A selected row exists even when no first-collection member resolves.
        assert_eq!(t.ready, vec![row(41, A, false)]);
        assert!(t.drain_ready().is_empty());
        assert!(t.ready.is_empty());
    }
}

#[test]
fn every_member_id_byte_participates_in_registry_lookup() {
    for offset in 0..32 {
        let mut different = ID;
        different[offset] ^= 1;
        let mut t = tracker();
        t.heights
            .get_mut(&41)
            .unwrap()
            .candidates
            .insert(A, [different].into());
        t.extract_selected(41, &registry(), 7);
        assert_eq!(t.ready, vec![row(41, A, false)]);
    }
}

#[test]
fn successful_members_are_remapped_and_missing_ones_are_dropped() {
    let other = [0x55; 32];
    let missing = [0x66; 32];
    let mut address2 = ADDRESS;
    address2[19] ^= 1;
    let r = [(7, [(ID, ADDRESS), (other, address2)].into())].into();
    let mut t = tracker();
    t.heights
        .get_mut(&41)
        .unwrap()
        .candidates
        .insert(A, [ID, other, missing].into());
    t.extract_selected(41, &r, 7);
    assert_eq!(t.ready[0].members, [ADDRESS, address2].into());
    assert_eq!(t.drain_ready().len(), 1);
}

#[test]
fn membership_projection_does_not_count_duplicate_addresses_as_threshold_votes() {
    let other = [0x55; 32];
    let r = [(7, [(ID, ADDRESS), (other, ADDRESS)].into())].into();
    let mut t = tracker();
    t.heights
        .get_mut(&41)
        .unwrap()
        .candidates
        .insert(A, [ID, other].into());
    t.extract_selected(41, &r, 7);
    assert_eq!(t.drain_ready()[0].members, [ADDRESS].into());
}

#[test]
fn empty_selected_candidate_is_queued_then_dropped() {
    let mut t = tracker();
    t.heights
        .get_mut(&41)
        .unwrap()
        .candidates
        .insert(A, BTreeSet::new());
    t.extract_selected(41, &registry(), 7);
    assert_eq!(t.ready, vec![row(41, A, false)]);
    assert!(t.drain_ready().is_empty());
}

#[test]
fn drain_is_stable_and_clears_even_an_all_filtered_queue() {
    let mut t = tracker();
    t.ready = vec![
        row(9, A, false),
        row(4, B, true),
        row(4, A, false),
        row(2, A, true),
    ];
    assert_eq!(t.drain_ready(), vec![row(4, B, true), row(2, A, true)]);
    assert!(t.drain_ready().is_empty());
    t.ready.push(row(1, A, false));
    assert!(t.drain_ready().is_empty());
    assert!(t.ready.is_empty());
}

#[test]
fn missing_local_history_is_a_skip_and_does_not_stop_later_rows() {
    let out = compare_prefix(&[row(1, B, true), row(2, A, true)], &[(2, A)].into());
    assert_eq!(
        out.iter().map(|x| x.comparison).collect::<Vec<_>>(),
        vec![Comparison::MissingLocal, Comparison::Equal]
    );
    assert_eq!(out[0].incoming, B);
    assert_eq!(out[0].local, None);
}

#[test]
fn height_is_an_exact_history_key_not_an_inferred_current_height() {
    let out = compare_prefix(
        &[row(40, A, true), row(41, A, true)],
        &[(40, A), (42, B)].into(),
    );
    assert_eq!(
        out.iter().map(|x| x.comparison).collect::<Vec<_>>(),
        vec![Comparison::Equal, Comparison::MissingLocal]
    );
}

#[test]
fn every_digest_byte_participates_and_mismatch_stops_the_prefix() {
    for offset in 0..32 {
        let mut changed = A;
        changed[offset] ^= 1;
        let out = compare_prefix(
            &[row(41, changed, true), row(42, A, true)],
            &[(41, A), (42, A)].into(),
        );
        assert_eq!(
            out,
            vec![Observation {
                height: 41,
                incoming: changed,
                local: Some(A),
                comparison: Comparison::Mismatch,
            }]
        );
    }
}

#[test]
fn extraction_observes_existing_state_without_reauthenticating_or_changing_it() {
    let mut t = tracker();
    let before = t.heights.clone();
    t.extract_selected(41, &registry(), 7);
    t.extract_selected(41, &registry(), 7);
    assert_eq!(t.heights, before);
    // Selection/timing policy is the caller's responsibility; no invented
    // deduplication by height or fresh signature check occurs at this boundary.
    assert_eq!(t.drain_ready(), vec![row(41, A, true), row(41, A, true)]);
}

#[test]
fn zero_and_maximum_height_remain_exact_keys_without_arithmetic() {
    let mut t = tracker();
    t.heights.insert(0, entry(Some(A), &[ID]));
    t.heights.insert(u64::MAX, entry(Some(A), &[ID]));
    t.extract_selected(u64::MAX, &registry(), 7);
    t.extract_selected(0, &registry(), 7);
    let rows = t.drain_ready();
    assert_eq!(rows, vec![row(u64::MAX, A, true), row(0, A, true)]);
    assert!(
        compare_prefix(&rows, &[(0, A), (u64::MAX, A)].into())
            .iter()
            .all(|x| x.comparison == Comparison::Equal)
    );
}

#[test]
fn entire_batch_reaches_sink_before_first_mismatch_diagnostic() {
    let out = replay_handoff(
        &[row(41, B, true), row(42, A, true)],
        &[(41, A), (42, A)].into(),
    );
    assert_eq!(out.sink_pairs, vec![(41, B), (42, A)]);
    assert_eq!(
        out.comparisons,
        vec![Observation {
            height: 41,
            incoming: B,
            local: Some(A),
            comparison: Comparison::Mismatch,
        }]
    );
}
