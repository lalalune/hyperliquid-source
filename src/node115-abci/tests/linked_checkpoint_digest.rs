use node115_abci::abci_hash::{blake3_hash, compute_linked_l1_digest};

const STATE: &[u8] = b"\x81\xa6height\x2a";
const MIXED: &str = "08347eacd591cca8d88e87cda875d7613bd1335081a915bf83f22a0379c288f9";

fn root() -> [u8; 32] {
    std::array::from_fn(|index| index as u8)
}

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn matches_independent_linked_l1_vectors() {
    let multi_chunk: Vec<_> = (0..1025).map(|index| (index % 251) as u8).collect();
    let cases: [(&[u8], &str); 3] = [
        (
            &[],
            "517935c568392e4fa5ebd476bc11f2b65b034001cbf6df95f706e542a2607afa",
        ),
        (STATE, MIXED),
        (
            &multi_chunk,
            "5ae7252aa7cc0999668e1472bdb0a274e02b75c0c9ca53e7c3cffb67030cc71c",
        ),
    ];
    for (state, expected) in cases {
        assert_eq!(hex(compute_linked_l1_digest(state, &root())), expected);
    }
}

#[test]
fn binds_active_span_and_preserves_raw_digest_order() {
    let mut backing = STATE.to_vec();
    backing.extend_from_slice(b"outside");
    let digest = root();
    let mixed = compute_linked_l1_digest(&backing[..STATE.len()], &digest);
    assert_eq!(hex(mixed), MIXED);
    assert_ne!(compute_linked_l1_digest(&backing, &digest), mixed);

    let state_hash = blake3_hash(STATE);
    let mut reversed = digest.to_vec();
    reversed.extend_from_slice(&state_hash);
    assert_ne!(blake3_hash(&reversed), mixed);

    let mut with_extra_height = state_hash.to_vec();
    with_extra_height.extend_from_slice(&digest);
    with_extra_height.extend_from_slice(&42u64.to_le_bytes());
    assert_ne!(blake3_hash(&with_extra_height), mixed);
}
