use std::io::{self, Write};

use node115_abci::lt_hash::{LT_HASH_BYTES, LtHash, LtHashes};

#[test]
fn named_sidecar_uses_decimal_arrays_and_ordered_counter_fields() {
    let mut all_values = [0; LT_HASH_BYTES];
    for (index, byte) in all_values.iter_mut().enumerate() {
        *byte = (index % 256) as u8;
    }
    let fixture = LtHashes {
        accounts_hash: LtHash {
            hash: all_values,
            n_elements: u64::MAX,
            n_bytes: 17,
        },
        contracts_hash: LtHash {
            hash: [10; LT_HASH_BYTES],
            n_elements: 0,
            n_bytes: u64::MAX,
        },
        storage_hash: LtHash {
            hash: [255; LT_HASH_BYTES],
            n_elements: 3,
            n_bytes: 255,
        },
    };
    let mut out = Vec::new();
    fixture.write_native_checkpoint_sidecar(&mut out).unwrap();

    let byte_ramp = (0..LT_HASH_BYTES)
        .map(|index| (index % 256).to_string())
        .collect::<Vec<_>>()
        .join(",");
    let tens = ["10"; LT_HASH_BYTES].join(",");
    let max_bytes = ["255"; LT_HASH_BYTES].join(",");
    let expected = format!(
        concat!(
            "{{\"accounts_hash\":{{\"n_elements\":18446744073709551615,\"n_bytes\":17,\"hash\":[{}]}},",
            "\"contracts_hash\":{{\"n_elements\":0,\"n_bytes\":18446744073709551615,\"hash\":[{}]}},",
            "\"storage_hash\":{{\"n_elements\":3,\"n_bytes\":255,\"hash\":[{}]}}}}"
        ),
        byte_ramp, tens, max_bytes
    );
    assert_eq!(String::from_utf8(out).unwrap(), expected);
}

struct LimitedWriter {
    remaining: usize,
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("write budget exhausted"));
        }
        let written = bytes.len().min(self.remaining);
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn sidecar_writer_propagates_partial_write_failure() {
    let error = LtHashes::new()
        .write_native_checkpoint_sidecar(LimitedWriter { remaining: 86 })
        .unwrap_err();
    assert_eq!(error.to_string(), "write budget exhausted");
}
