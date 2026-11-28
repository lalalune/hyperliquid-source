# RE-009 · Compare a node #115 linked digest against pinned state and raw ABCI records

A linked hardfork digest can cross-check a separately supplied raw ABCI digest when the exact serializer bytes and native linked record are available. This command binds three local artifacts by SHA-256, checks both record heights, and reports the two digest types separately.

| Input | Required bytes |
| --- | --- |
| Serialized state | The exact byte slice returned as pointer and length on the selected native serializer route. Pass only that slice, without neighboring bytes, unconsumed buffer capacity, or an added height trailer. |
| Raw ABCI export | One native `abci_hashes` row with its own height and 32-byte `abci_digest`. |
| Linked reference | One 40-byte `hardfork_hashes` worker message with little-endian height at bytes 0–7 and a 32-byte linked digest at bytes 8–39. |

The existing [hardfork worker evidence](../RE-008-hardfork-hashes-115/README.md) shows the serialized state and raw ABCI inputs and the 40-byte message published on the selected channel. The [native linked digest packet](../RE-008-l1-hash-input-115/README.md) establishes the composition `BLAKE3(BLAKE3(serialized_state) || raw_abci_digest)`. [#7283](https://github.com/lalalune/hyperliquid-source/pull/7283) pins the byte slice, keeps the height metadata outside the hash and supplies independent test vectors. [#7318](https://github.com/lalalune/hyperliquid-source/pull/7318) compares same-height raw digests between captures. This command checks the independent linked message against the exact supplied state extent and raw value.

The Rust helper reads the state slice in chunks. Python measures its SHA-256 over those same streamed bytes. The output records the height, exact length, intermediate BLAKE3, raw ABCI digest, and expected and calculated linked digests. Exit status 0 means linked equality, 1 means a measured mismatch, and 2 means invalid input. The check does not recover the native byte slice from an arbitrary checkpoint container or authenticate the artifact's producer. A genuine linked record remains a prerequisite for making an independent claim. No actual H/H+1 comparison is represented by the synthetic tests.

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

From the repository root with the pinned artifact available and Rust 1.95 on PATH:

```sh
packet=research/work-items/RE-009-node115-linked-root-receipt
python3 -B "$packet/verify.py"

build_dir=$(mktemp -d)
rustc --edition=2024 --crate-name node115_abci_blake3 --crate-type rlib \
  src/node115-abci-blake3/src/lib.rs -o "$build_dir/libnode115_abci_blake3.rlib"
rustc --edition=2024 "$packet/linked.rs" \
  --extern "node115_abci_blake3=$build_dir/libnode115_abci_blake3.rlib" -o "$build_dir/linked"
python3 -B "$packet/compare.py" "$build_dir/linked" HEIGHT \
  STATE_BYTES STATE_SHA256 RAW_EXPORT.jsonl RAW_EXPORT_SHA256 \
  HARDFORK_MESSAGE.bin HARDFORK_MESSAGE_SHA256
```

The [offline log](offline-log.txt) shows native writer and formula checks, both independent vectors, height and byte-width rejection, exact-length controls and all three SHA-256 pins.
