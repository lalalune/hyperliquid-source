# Digest key history: address mapping and eligibility on the same owner

Target: `node/115`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes. This is static reconstruction: the target was neither executed nor emulated.

## Contribution and prior work

This supplies a Rust logical implementation of reverse address-to-key lookup and exact-key eligibility, and traces their actual shared caller object. It advances the RE-017 digest-admission boundary and the state-validation path; it does not establish a trusted consensus root.

The existing `staking-snapshot-members-115` packet already establishes the reverse lookup at `0x36ca5b0`, including its last-match rule and raw result tags. `RE-008-node115-signer-membership-lookup` already establishes `0x37141b0` and its container variants (including work associated with #2594 and #5371). `RE-017-hash-signature-record-115` establishes surrounding call/result shapes. Those static helper semantics are reused, not claimed as discoveries here. The new source and the address/key same-owner composition are the remaining scope. PR #7053's new-vote admission model accepts eligibility at a boundary; this crate is a candidate implementation of that boundary, without copying or depending on the unmerged PR.

## Actual caller chain

Let `S` be the state passed to `0x294fdd0`. That wrapper digests the message through `0x38d2b00`, calls the existing signature primitive at `0x1536a90` through slot `0x64e0ad8`, and compares all 20 recovered bytes with its expected address. Signature correctness remains an upstream contract.

On the selected success path it constructs a record whose `+0x30` field is that expected address. It calls `0x2760bc0` with tracker `S+0x3e50` and fifth argument `E = S+0x3f08`. The other provider is `S+0xd88`; it must not be confused with E.

`0x2760bc0` saves E at stack `+0x38`. At `0x2760daa..0x2760dbb`, it invokes `0x36ca5b0(out, E, record+0x30, *(E+0x58))`. Only raw tag `0x1a2` produces the optional 32-byte key. The incoming record's height is a separate field: it does not choose this history row.

The call to `0x28b2f10` passes E as the seventh argument. Specifically, after pushing the eighth argument at `0x2760f58`, the push of `[rsp+0x40]` at `0x2760f59` reads the original saved E at `rsp+0x38`. The callee's six pushes and `0x398` frame put that seventh argument at `rsp+0x3d0`. At `0x28b327d..0x28b3295`, it loads that exact E, calls `0x37141b0(E, key)` through slot `0x64e6ac0`, and rejects a false result before admission.

Thus both helpers receive the same object. This does **not** prove locking, an immutable native snapshot, absence of intervening mutation, or authority/provenance of `E+0x58`. The Rust `Snapshot` is an explicitly immutable logical input for each call. Its stored selector is not labeled an epoch or height.

## Lookup contracts

Both helpers select an exact u64 row in the history at E, using a tree or the wrapped sorted-ring search `0x4551810`. No closest/older row fallback exists. The reverse helper receives the selector as an argument; the membership helper reads `E+0x58` itself.

`0x36ca5b0` traverses the selected inner map in logical order. The ring row stride is `0x68`: the key is the first 32 bytes, and the compared 20-byte address is at row `+0x40`. In the tree, iterator `0x37c5530` yields key and value pointers, with that address at value `+0x20`. A matching address overwrites the candidate and traversal continues. Therefore multiple distinct keys for the same address return the **last matching logical key**. Raw tags are `0x9b` for no history row, `0x2b` for no address, and `0x1a2` plus the 32-byte key for success. This is a map lookup, not cryptographic recovery.

`0x37141b0` checks the entire 32-byte key in the selected inner tree or wrapped ring (`0x4559a60`). An absent outer row produces a diagnostic and false; an absent inner key also returns false. The source omits diagnostics and other unused fields in the 72-byte native value.

## Source interface and premises

`src/node115-vote-eligibility` offers `Snapshot::key_for_address` and `Snapshot::eligible`, with tree and ring representations for each level. Sorted unique keys, valid live lengths and valid ring geometry are native input premises. Checked ring constructors reject malformed inputs as a host-interface guard; that is not a recovered native admission rule. Public enum variants can represent invalid inputs, so callers bypassing those constructors retain those premises. `BTreeMap` represents logical order, not the native allocation layout or performance.

The implementation does not model cryptography, mutation, native refcounts, allocator behavior, panic/unwind cleanup, history writers, selector freshness, or consensus authority. A returned mapping's membership under the same immutable Rust input is a source property; it does not establish native atomicity across the two calls.

## Validation

`records.json` retains seven complete FDEs and two bounded caller windows: nine windows, 1,108 instructions, 146 selected instruction witnesses, three resolved relocations, one import binding and 13 negative controls. `verify.py` checks the exact target, bytes, instruction transcription, FDE coverage and selected relations, then rejects deliberately changed witnesses.

The crate tests cover missing rows versus missing addresses, duplicate-address last-match selection, full 32-byte membership, exact selector changes, wrapping, inactive padding and invalid constructor geometry. An independent linear oracle exercises all four outer/inner representation combinations, outer and inner rotations, IDs 0 and u64::MAX, missing interior selectors, and address/key differences only in their final byte. The oracle does not call the native target.

Run the native verifier through the work-item reproduction entry, and run `cargo +1.95.0 test`, `cargo +1.95.0 test --release`, formatting and strict Clippy for the crate. Packaging records the exact source and evidence hashes and the repository's static validation results.
