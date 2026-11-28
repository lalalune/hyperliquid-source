use node115_abci::lt_hash::{CompactLtHashFixtureError, LT_HASH_BYTES, LtHash, LtHashes};

fn complete_fixture() -> (Vec<u8>, LtHashes) {
    let expected = LtHashes {
        accounts_hash: LtHash {
            hash: [0x12; LT_HASH_BYTES],
            n_elements: 5,
            n_bytes: 103,
        },
        contracts_hash: LtHash {
            hash: [0x34; LT_HASH_BYTES],
            n_elements: u64::MAX,
            n_bytes: 28,
        },
        storage_hash: LtHash {
            hash: [0x56; LT_HASH_BYTES],
            n_elements: 0,
            n_bytes: u64::MAX,
        },
    };
    let mut image = vec![0xa5; 0x42c8];
    image[0x28..0x30].copy_from_slice(&412_u64.to_le_bytes());
    for (offset, hash) in [
        (0x1200, &expected.accounts_hash),
        (0x1b08, &expected.contracts_hash),
        (0x2410, &expected.storage_hash),
    ] {
        image[offset..offset + 0x800].copy_from_slice(&hash.hash);
        image[offset + 0x800..offset + 0x808].copy_from_slice(&hash.n_elements.to_le_bytes());
        image[offset + 0x808..offset + 0x810].copy_from_slice(&hash.n_bytes.to_le_bytes());
    }
    (image, expected)
}

#[test]
fn materialized_records_feed_the_existing_rust_lthash_operations() {
    let (mut image, expected) = complete_fixture();
    let actual = LtHashes::from_compact_checkpoint(&image, 412).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual.checksums(), expected.checksums());

    image[0x1b08 + 0x800] ^= 1;
    let counter_change = LtHashes::from_compact_checkpoint(&image, 412).unwrap();
    assert_ne!(
        counter_change.contracts_hash.n_elements,
        actual.contracts_hash.n_elements
    );
    assert_eq!(counter_change.checksums(), actual.checksums());

    image[0x2410 + 0x7ff] ^= 1;
    let payload_change = LtHashes::from_compact_checkpoint(&image, 412).unwrap();
    let (accounts, contracts, storage) = payload_change.checksums();
    let (old_accounts, old_contracts, old_storage) = actual.checksums();
    assert_eq!((accounts, contracts), (old_accounts, old_contracts));
    assert_ne!(storage, old_storage);
}

#[test]
fn compact_input_must_have_the_exact_size_and_requested_height() {
    let (mut image, _) = complete_fixture();
    assert_eq!(
        LtHashes::from_compact_checkpoint(&image[..0x42c7], 412),
        Err(CompactLtHashFixtureError::WrongSize { actual: 0x42c7 })
    );
    assert_eq!(
        LtHashes::from_compact_checkpoint(&image, 413),
        Err(CompactLtHashFixtureError::HeightMismatch {
            expected: 413,
            actual: 412
        })
    );
    image.resize(0x4e38, 0);
    assert_eq!(
        LtHashes::from_compact_checkpoint(&image, 412),
        Err(CompactLtHashFixtureError::WrongSize { actual: 0x4e38 })
    );
}
