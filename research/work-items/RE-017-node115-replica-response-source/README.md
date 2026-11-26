# Replica response JSON source for the selected branch

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes). Linked virtual addresses. Base: `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`.

## Question and prior work

`RE-017-node115-replica-response-json` / #4161 identifies the null/Hash/Full dispatch and nested row layout without producing response bytes in project Rust. `RE-017-node115-replica-action-response-status` / #4162 identifies a separate inner action-entry writer. `RE-008-abci-hashes-tree-json-115` and #6031 establish the shared fixed-byte hex adapter and lowercase alphabet. This packet reuses those findings and adds an independently authored output writer that connects the parent branches to the ordered nested rows; it does not reimplement the action-entry payload.

## Bounded result

On ordinarily returning paths, `0x506e230` emits `null` for tag 2. `0x4d6d170` emits one named object: tag 1 names `Hash` and passes bytes at +1 to `0x4e1c250`; its Full arm names `Full` and invokes `0x502d0d0` on +8. `0x4e1c250` writes quotes around the result of `0x2eabb50`, reached through relative slot `0x64e4d08`; for 32 bytes and trim zero the latter writes `0x` followed by 64 lowercase digits. Full's writer emits an ordered outer array of pairs: each 0x38-byte row contributes its leading 32-byte hash and an ordered nested array of 0x40-byte action entries. Empty arrays are retained. A nonzero entry-writer result exits before the remaining punctuation; it does not establish native allocation-failure semantics.

`src/node115-replica-response-json` emits real bytes for these branches and accepts an entry-writer callback for the separately recovered entry payload. The callback's host `io::Error` is propagated immediately, preserving the bytes already written and skipping later entries. This is a logical ordering/error boundary, not a claim that native writer error representations equal `io::Error`, nor proof of partial-write behavior inside native vector growth. Source types, arbitrary native tags, malformed native layouts, entry escaping, all allocations and runtime ABI remain out of scope. The `Hash` field is not asserted to equal a state root or have a known preimage.

## Evidence and validation

`records.json` retains exact SHA-256 body hashes and bounds of five FDEs (2,692 bytes total), 29 selected instruction bytes, the four-byte field literals, lowercase digit table and relocation target. These are evidence extents, not reconstructed code or source equivalence denominators. `verify.py` authenticates target identity, FDE ranges, whole-body hashes, each witness, literals and relative relocation, then rejects 29 single-byte witness corruptions below the whole-image guard. Instruction spelling was collected with GNU objdump 2.47.20260726. It never executes the target.

```sh
python3 research/work-items/RE-017-node115-replica-response-source/verify.py --target artifacts/node/115/hl-node
cargo test --offline --locked --manifest-path src/node115-replica-response-json/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-replica-response-json/Cargo.toml
cargo fmt --manifest-path src/node115-replica-response-json/Cargo.toml -- --check
cargo clippy --offline --locked --all-targets --manifest-path src/node115-replica-response-json/Cargo.toml -- -D warnings
```

Tests compare independently constructed literal JSON for null, Hash and multiple Full rows (including empty/nonempty entry arrays) and test first-child failure with a preserved prefix. The numeric entry values in the Full fixture are valid JSON stand-ins passed by the callback; they are not claimed to be native action-entry encodings. The `user` adapter is not yet qualified here, so no fabricated user representation is asserted. Tests do not execute the target or prove entry serialization or whole-response native equivalence. Full component gates remain false.
