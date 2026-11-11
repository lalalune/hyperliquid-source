# Ordinary validator snapshot publication and the selected admission epoch

Target: node115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Related issue: #3928. Backlog question HL115-017 is **partially addressed**.

## Result and remaining boundary

The ordinary publisher at `0x36cab90` can publish a newer validator snapshot without changing the epoch selected by signer membership checks. It advances the selected epoch only in its bootstrap case, using the **old next key**, not the requested publication key. The selected lookup still searches exactly the stored selected key; it does not use the newest snapshot or the active member map.

This connects a previously excluded writer to the existing selected-snapshot consumer on the same Exchange layout. It does not reconstruct complete signed-action authorization. The separate forced path calls an authorization helper before publication and explicitly writes the selected epoch afterward; that path is recorded below as an unresolved dependency, not modeled with a supplied `authorized` boolean. Initialization and a complete census of all aliased writers remain open.

## Prior work and novelty

The existing `staking-validator-snapshot-lookup-115` packet establishes the exact-key history search, full20-byte signer match and diagnostics `0x9b`/`0x2b`, excluding the writer. `staking-admission-gate-115` identifies its callers and their `Exchange+0x3f08` owner. These results are credited and composed here, not presented as new lookup discoveries. PR #1746 concerns the older node94 clone/update/prune path: its target is not interchangeable with node115. Recent #5371, #5372, #5378 and #5382 inspect related lookup/consumer paths, not this writer-to-selected-view transition. The current packet adds the node115 writer, calendar bucket conditions, separate publication/selection keys, caller bindings and owned transition tests.

## Object and caller binding

In the selected layout the store is `Exchange+0x3f08`: history map at +0, active member map at +0x20 (length +0x38), packed Moment at +0x40 (12 bytes), nonzero period at +0x50, selected epoch +0x58 and next publication key +0x60. Member records have a distinct32-byte key and a20-byte signer at row+0x40; the signer is not the map key.

`0x2bdf916..0x2bdf96c` and `0x54b66d6..0x54b672c` load the Exchange pointer, skip the publisher when Exchange+0x28 is zero, pass raw byte+0xb9a, copy Moment+0x60, and pass next key+0x3f68 to `0x36cab90`. Subsequent caller effects are outside this source contract. On the consumer side `0x4d9080e` forms the same +0x3f08 store and `0x4d9081a` calls slot `0x64e4e38 -> 0x36c8430`; `0x2bdb230` is another bound gate. The third gate `0x4d909b0` uses a different +0x4a78 layout and is deliberately not conflated with these owners.

## Publisher transition

On valid input and normal helper return:

1. `0x36caba3` rejects requested key < old next key without mutation.
2. `0x36cabba..0x36cad23` computes old/new buckets: clamp the packed Gregorian Moment's Unix seconds to zero, then divide by the nonzero period. Nanoseconds and the low4 date bits do not participate. Packed year is arithmetic date>>13; ordinal is (date>>4)&511. The calendar formula is `365*(y-1)+floor((y-1)/4)-floor((y-1)/100)+floor((y-1)/400)+ordinal-719163` days. The negative-year400-cycle correction is checked independently over the full packed-year range by `proof_checks.py`.
3. Bootstrap at `0x36cad14..0x36cad39` means selected==0 and (raw flag!=0 or active length==3). Unless bootstrap, new bucket must be strictly greater. This does not identify a named network from the raw flag.
4. Clone active members via `0x39221a0` (tree), `0x457fdc0` (flat), or the empty path. `0x36cadc2..0x36cadf9` appends the **old** Moment to the cloned snapshot. `0x36cae11 -> 0x3cdad90` inserts/replaces under the requested key. Replacement swaps the48-byte old/new snapshot at `0x3cdb0e7..0x3cdb113`; old owned contents are cleaned up.
5. Only if bootstrap, `0x36caeca..0x36caece` copies old next+0x60 to selected+0x58. This equals requested key in the ordinary callers but is not generally identical for direct calls.
6. `0x36caed2..0x36caee0` sets next=requested.saturating_add(1), including MAX->MAX. `0x36caee4..0x36caef3` copies the new12-byte Moment to the store.
7. If history length>=1001, inspect its minimum key, then remove it only when minimum<selected (`0x36cafc8..0x36cafcc` flat; `0x36cb042..0x36cb049` tree). `0x36cb055 -> 0x3ceb2f0` removes that minimum. Stop at length<=1000 or a protected minimum>=selected; the history can legitimately remain larger than1000. The flat helper advances head and decrements length; the tree path descends to its leftmost leaf and delegates removal.

Normal allocation, logically valid ordered maps and successful ordinary clone/insert/pop contracts are explicit premises. We retain native helper windows but do not claim to close every allocator, physical map conversion, balancing, cleanup/unwind or logging dependency. The source uses owned `BTreeMap` values and Rust cloning, not native pointers or transplanted container code.

## Selected view and another writer

Lookup `0x36c8441` reads selected+0x58. An absent exact history key emits diagnostic0x9b; present key without the full20-byte signer emits0x2b. These are lookup diagnostics, not the enclosing gate's final error status. Source exposes only this membership subcheck.

The force-related handler also has a post-authorization path: `0x36ca2b8 -> 0x36c7f70`, test at `0x36ca2bd`, publisher at `0x36ca2dc`, successful-return test at `0x36ca2e1`, then `0x36ca2e9..0x36ca2f1` writes a stack-carried epoch to+0x58. Its upstream signature/hash/threshold reasoning and epoch provenance are not implemented. Therefore this packet does **not** claim that ordinary publication is the only way to advance selection or that HL115-017 is wholly finished.

## Reproduction

From the repository root, with Capstone5.0.7 and Python3:

```
python3 research/work-items/RE-017-node115-validator-snapshot-publication/verify.py
python3 research/work-items/RE-017-node115-validator-snapshot-publication/proof_checks.py
cargo +1.95.0 test --offline --manifest-path src/node115-validator-snapshot-publication/Cargo.toml
cargo +1.95.0 test --offline --release --manifest-path src/node115-validator-snapshot-publication/Cargo.toml
cargo +1.95.0 clippy --offline --all-targets --manifest-path src/node115-validator-snapshot-publication/Cargo.toml -- -D warnings
```

The verifier authenticates the complete ELF digest, containing FDEs, instruction windows, direct/relocated edges and semantic corruption controls. Corruption controls overlay one fact only after authenticating the original target, bypassing the whole-file/window hashes so fact rejection is exercised. They do not prove the interpretation by themselves. Logical calendar checks are algebraic formulas, not an instruction interpreter. Rust tests include an independent day-by-day calendar reference, bucket/stale no-op ordering, all bootstrap combinations, old/new Moment separation, clone ownership, selection visibility, key gaps, saturation/replacement and protected pruning. No original target code is executed or emulated. Full staking/consensus/ABCI component gates remain false.
