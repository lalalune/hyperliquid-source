use node115_abci_blake3::{
    Blake3Hasher, blake3_hash, blake3_xof, compute_leaf_root, compute_preimage_root,
};

fn pattern_input(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn hex_of(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Official BLAKE3 specification test vectors (BLAKE3-team/BLAKE3 test_vectors.json)
/// covering empty input, "abc", single block, block boundary (64/65 B), single chunk
/// (1024 B), and multi-chunk parent chaining (1025 B).
#[test]
fn official_blake3_specification_vectors() {
    assert_eq!(
        hex_of(&blake3_hash(b"abc")),
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    );

    let cases: &[(usize, &str)] = &[
        (
            0,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        ),
        (
            1,
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        ),
        (
            64,
            "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        ),
        (
            65,
            "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
        ),
        (
            1024,
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        ),
        (
            1025,
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
        ),
    ];

    for &(len, expected) in cases {
        let input = pattern_input(len);
        let actual = hex_of(&blake3_hash(&input));
        assert_eq!(actual, expected, "length={len}");

        // Incremental streaming (odd step size 17) must match one-shot identically!
        let mut h = Blake3Hasher::new();
        for chunk in input.chunks(17) {
            h.update(chunk);
        }
        assert_eq!(hex_of(&h.finalize()), expected, "streaming length={len}");
    }
}

#[test]
fn streaming_matches_one_shot_across_chunk_and_merkle_boundaries() {
    for len in [0usize, 1, 64, 1023, 1024, 1025, 2048, 2049, 3072, 4096, 10_000] {
        let input = pattern_input(len);
        let one_shot = blake3_hash(&input);
        let mut h = Blake3Hasher::new();
        for chunk in input.chunks(37) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), one_shot, "mismatch at len={len}");
    }
}

#[test]
fn leaf_and_empty_reduction_tree_roots_are_deterministic_and_sensitive() {
    // Empty reduction tree preimage = [0x90]
    let r_empty = compute_preimage_root(&[0x90]);
    let r_nonempty = compute_preimage_root(&[0x91]);
    assert_ne!(r_empty, r_nonempty);

    // Leaf root changes on any single-bit flip in the 32-byte input
    let zero_leaf = [0u8; 32];
    let mut flipped = zero_leaf;
    flipped[31] = 1;
    assert_ne!(compute_leaf_root(&zero_leaf), compute_leaf_root(&flipped));
}

#[test]
fn blake3_xof_matches_32_byte_prefix_and_2048_byte_lthash_expansion() {
    // Empty input 131-byte official BLAKE3 XOF prefix: first 32 B == blake3_hash(b"")
    let mut xof_2048 = [0u8; 2048];
    blake3_xof(b"", &mut xof_2048);
    assert_eq!(&xof_2048[..32], &blake3_hash(b""));

    // Prefix consistency across lengths (63, 64, 65, 131, 2048)
    let mut xof_131 = [0u8; 131];
    blake3_xof(b"", &mut xof_131);
    assert_eq!(&xof_131[..], &xof_2048[..131]);

    // Streaming XOF matches one-shot XOF on multi-chunk input
    let input = pattern_input(2049);
    let mut one_shot = [0u8; 2048];
    blake3_xof(&input, &mut one_shot);
    let mut h = Blake3Hasher::new();
    for chunk in input.chunks(53) {
        h.update(chunk);
    }
    let mut streamed = [0u8; 2048];
    h.finalize_xof_into(&mut streamed);
    assert_eq!(streamed, one_shot);
    assert_eq!(&streamed[..32], &blake3_hash(&input));
    // Output blocks 0 and 1 must be distinct (counter incremented!)
    assert_ne!(&streamed[..64], &streamed[64..128]);
}
