use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use node115_abci::lt_hash::{LtHash, LtHashes};
use node115_abci::state::{AbciCheckpointBundle, CheckpointBundleError};

fn lane(seed: u8, n_elements: u64, n_bytes: u64) -> LtHash {
    LtHash {
        hash: std::array::from_fn(|index| (index as u8).wrapping_add(seed)),
        n_elements,
        n_bytes,
    }
}

fn json_lane(value: &LtHash) -> String {
    let bytes = value.hash.iter().map(u8::to_string).collect::<Vec<_>>();
    format!(
        "{{\"n_elements\": {}, \"n_bytes\": {}, \"hash\": [{}]}}",
        value.n_elements,
        value.n_bytes,
        bytes.join(", "),
    )
}

#[test]
fn checkpoint_bundle_loads_native_byte_arrays_alongside_legacy_hex() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let checkpoint =
        std::env::temp_dir().join(format!("hl-sidecar-{}-{nanos}", std::process::id()));
    let bundle = AbciCheckpointBundle {
        height: 10_000,
        round: 901,
        hardfork_version: 115,
        hardfork_height: None,
        lt_hashes: LtHashes {
            accounts_hash: lane(0, 0, 1),
            contracts_hash: lane(37, 2, 3),
            storage_hash: lane(255, u64::MAX, 5),
        },
    };
    bundle.save_to_checkpoint_dir(&checkpoint).unwrap();
    assert_eq!(
        AbciCheckpointBundle::load_from_checkpoint_dir(&checkpoint, 115).unwrap(),
        bundle
    );

    let sidecar = checkpoint.join("lt_hashes.json");
    let named = format!(
        "{{\"accounts_hash\": {},\n\"contracts_hash\": {},\n\"storage_hash\": {}}}\n",
        json_lane(&bundle.lt_hashes.accounts_hash),
        json_lane(&bundle.lt_hashes.contracts_hash),
        json_lane(&bundle.lt_hashes.storage_hash),
    );
    fs::write(&sidecar, &named).unwrap();
    let native = AbciCheckpointBundle::load_from_checkpoint_dir(&checkpoint, 115);
    for replacement in ["", "256", "00"] {
        fs::write(
            &sidecar,
            named.replacen("[0, ", &format!("[{replacement}, "), 1),
        )
        .unwrap();
        assert!(matches!(
            AbciCheckpointBundle::load_from_checkpoint_dir(&checkpoint, 115),
            Err(CheckpointBundleError::CorruptPayload("accounts_hash")),
        ));
    }
    for malformed_prefix in ["[", "[0, 0, "] {
        fs::write(&sidecar, named.replacen("[0, ", malformed_prefix, 1)).unwrap();
        assert!(matches!(
            AbciCheckpointBundle::load_from_checkpoint_dir(&checkpoint, 115),
            Err(CheckpointBundleError::CorruptPayload("accounts_hash")),
        ));
    }
    fs::remove_dir_all(&checkpoint).unwrap();
    assert_eq!(
        native.expect("must load native decimal-array sidecar"),
        bundle
    );
}
