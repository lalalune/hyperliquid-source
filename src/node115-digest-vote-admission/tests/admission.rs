use node115_digest_vote_admission::{
    Admission, Candidate, Digest, HeightEntry, Snapshot, Voter, admission_for,
};

fn digest(n: u64) -> Digest {
    let mut result = [0; 32];
    result[..8].copy_from_slice(&n.to_le_bytes());
    result
}

fn one_height(count: u64, voter: Voter) -> Snapshot {
    let mut entry = HeightEntry::default();
    for n in 0..count {
        let mut candidate = Candidate::default();
        match voter {
            Voter::Key32(k) => {
                candidate.keys32.insert(k);
            }
            Voter::Key20(k) => {
                candidate.keys20.insert(k);
            }
        }
        entry.candidates.insert(digest(n), candidate);
    }
    [(1, entry)].into_iter().collect()
}

#[test]
fn both_families_obey_incidence_boundary() {
    for voter in [Voter::Key32([3; 32]), Voter::Key20([4; 20])] {
        for (n, expected) in [
            (2199, Admission::AdmitNew { count: 2199 }),
            (2200, Admission::AtCapacity { count: 2200 }),
            (2201, Admission::AtCapacity { count: 2201 }),
        ] {
            let snapshot = one_height(n, voter);
            let before = snapshot.clone();
            assert_eq!(
                admission_for(&snapshot, 2, digest(u64::MAX), voter, true),
                expected
            );
            assert_eq!(snapshot, before);
        }
    }
}

#[test]
fn selected_exclusion_is_per_height_and_key_families_are_distinct() {
    let voter = Voter::Key20([7; 20]);
    let mut snapshot = one_height(3, voter);
    snapshot.get_mut(&1).unwrap().selected = Some(digest(1));
    let other = one_height(2, voter).remove(&1).unwrap();
    snapshot.insert(2, other);
    assert_eq!(
        admission_for(&snapshot, 3, digest(99), voter, true),
        Admission::AdmitNew { count: 4 }
    );
    assert_eq!(
        admission_for(&snapshot, 3, digest(99), Voter::Key20([8; 20]), true),
        Admission::AdmitNew { count: 0 }
    );
    assert_eq!(
        admission_for(&snapshot, 3, digest(99), Voter::Key32([7; 32]), true),
        Admission::AdmitNew { count: 0 }
    );
}

#[test]
fn guards_precede_existing_candidate_and_count() {
    let voter = Voter::Key20([5; 20]);
    let mut snapshot = one_height(2200, voter);
    assert_eq!(
        admission_for(&snapshot, 1, digest(0), voter, true),
        Admission::ExistingCandidate
    );
    snapshot.get_mut(&1).unwrap().selected = Some(digest(1));
    assert_eq!(
        admission_for(&snapshot, 1, digest(1), voter, true),
        Admission::ExistingCandidate
    );
    assert_eq!(
        admission_for(&snapshot, 1, digest(0), voter, true),
        Admission::ConflictingSelection
    );
    assert_eq!(
        admission_for(&snapshot, 1, digest(0), voter, false),
        Admission::NotEligible
    );
}

#[test]
fn later_family_observes_actual_updated_snapshot() {
    let key32 = Voter::Key32([1; 32]);
    let key20 = Voter::Key20([2; 20]);
    let mut snapshot = one_height(2200, key20);
    let new_digest = digest(u64::MAX);
    assert_eq!(
        admission_for(&snapshot, 2, new_digest, key32, true),
        Admission::AdmitNew { count: 0 }
    );
    assert_eq!(
        admission_for(&snapshot, 2, new_digest, key20, true),
        Admission::AtCapacity { count: 2200 }
    );
    let mut inserted = Candidate::default();
    inserted.keys32.insert([1; 32]);
    snapshot
        .entry(2)
        .or_default()
        .candidates
        .insert(new_digest, inserted);
    assert_eq!(
        admission_for(&snapshot, 2, new_digest, key20, true),
        Admission::ExistingCandidate
    );
}
