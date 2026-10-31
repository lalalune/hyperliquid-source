# fees: the referral state of one user in node #94, stage, row order and cap

This packet shows how node #94 turns a user into one of three referral stages: `needToTrade` with `(1000000 - sum) / 100` still required, 10000.0 when the user has no fee row, `needToCreateCode` from a sum of 1000000, or `ready` with the code and the referred users that hold a fee row, sorted by `cumRewardedFeesSinceReferred` from largest to smallest in f64 total order with `nReferrals` counted before an optional cap of 5000 rows, and that the file snapshot path never turns that cap on, so a reconstruction can now write the `referrerState` shape, the row order and the snapshot filter, and the missing `referrerStates` builder of `fees-collection-94` is found.

- Component ID: `fees` (first task: maker/taker fee formulas and time-window rollover; this packet fixes the referrer side of the referral view, the rollover stays open).
- Target release and full SHA-256: hl-node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only, nothing copied).
- Claim status: observation for bytes, decoded instructions and evaluated outcomes; inference where marked; unresolved items are listed at the end.
- Scope included: stage builder `0x2a2b0a0`, row walker `0x2a10940`, row lookup `0x2a2c6c0`, iterators `0x2a0a030`, `0x330ed70`, `0x2a0a440`, short sort `0x2a1ff20`, cap `0x2a39bd0`, approved builder list `0x2a2b5f0`, folders `0x251bf90`, `0x251c680`, and key names and offsets of the serializers `0x22cf340`, `0x22cec10`. Scope excluded: the row core `0x2a2a9f0` (listed by #811, so a stub here), the long sort `0x2a40430`, the hash `0x2a39350`, the lock wrappers `0x27dca30`, `0x258a0b0` and the rayon drivers above the folders.

## Reproduce

Run from the repository root:

```
python3 tools/fees_referral_state.py --out research/work-items/fees-referral-state-94
cd research/work-items/fees-referral-state-94 && sha256sum -c MANIFEST.sha256
python3 -m unittest tests.test_fees_referral_state
```

Python 3 standard library only. The tool refuses any binary whose SHA-256 differs from the value above, never runs the binary, and calls no external program. Sections and FDE data come from `tools/elf_index.py` and `tools/fde_extents.py`. A full run takes about 220 s on 4 workers.

## Evidence

Coordinates are virtual addresses in the ELF above. Every generated number comes from bytes. Key names come from `.rodata` through the pins in `evidence.json`.

### Boundaries

| Address | FDE end | Role | Decoded / executed |
|---|---|---|---|
| 0x251bf90 | 0x251c2d8 | folder | 191 / 174 |
| 0x251c680 | 0x251c9c8 | folder, +0xa80 shape | 191 / 174 |
| 0x2a0a030 | 0x2a0a22b | next of the joined tree | 122 / 116 |
| 0x2a0a440 | 0x2a0a62f | next of the builder tree | 120 / 114 |
| 0x2a10940 | 0x2a10e6e | row walker | 281 / 217 |
| 0x2a1ff20 | 0x2a20085 | short sort | 83 / 81 |
| 0x2a2b0a0 | 0x2a2b5ef | stage builder | 298 / 280 |
| 0x2a2b5f0 | 0x2a2b851 | approved builder list | 151 / 140 |
| 0x2a2c6c0 | 0x2a2c7f5 | row lookup | 81 / 81 |
| 0x2a39bd0 | 0x2a39d5c | take n rows in place | 100 / 83 |
| 0x330ed70 | 0x330ef78 | next of the token tree | 122 / 116 |

### Path

Slot `0x5774598` holds `0x2a2b0a0`. It has 2 users, `0x251c1ad` in `0x251bf90` and `0x251c89d` in `0x251c680`. Slot `0x5774f30` holds `0x2a2b5f0`, used once in `0x27dca30`. `call-sites.tsv` lists these and the direct calls.

Arguments of `0x2a2b0a0`: rdi result, rsi fee tracker, rdx 20-byte user, rcx spot context, r8d flag (only the low byte is read).

1. The user is searched in the B-tree at tracker `+0x108` (root), `+0x110` (height). Node layout: keys 20 bytes at `+0x320`, count u16 at `+0x3fe`, children at `+0x400`, values `0x48` bytes at `+8`. A null root is a miss.
2. Miss, no row: when tracker `+0xd8` is 0 or the user has no row in the table at `+0xc0` (stride `0xe8`), the result is `needToTrade` with the f64 at `0x20a830`, 10000.0.
3. Miss, row: the first word of each `0x30`-byte value in the token tree of the row (root, height, length at item end `-0x38`, `-0x30`, `-0x28`) is summed in key order. Each add saturates and calls the recorder at slot `0x5773190` with `l1/src/qtys/impl_ntl.rs:664:1`. A sum of at least 1000000 gives `needToCreateCode`. Below that, `needToTrade` with `(1000000 - sum) / 100.0`. So 1 unit short reads 0.01.
4. Hit: the code text (value `+8`, `+0x10`) is copied to a new allocation of exact size, and the joined tree (value `+0x20` root, `+0x28` height, `+0x30` length) is walked in key order. Node layout: keys 20 bytes at `+8`, 12-byte times at `+0xe4`, parent `+0`, index `+0x168`, count `+0x16a`, children `+0x170`.
5. Each joined user is looked up in the same table. A miss is dropped with no trace. A hit calls the row core through slot `0x5775378` with the time, the user, item end `-0xd0` and the spot context, and pushes the `0x50`-byte row. The first push allocates 4 rows.
6. Rows are sorted by the f64 at row `+8`, largest first in total order, stable: under 21 rows through `0x2a1ff20`, otherwise through `0x2a40430`. In this order NaN with a clear sign is first, and NaN with a set sign is last. Plus zero sorts before minus zero.
7. `nReferrals` is the row count after step 5 and before any cap. When the low byte of the flag is not 0, `0x2a39bd0` keeps the first 5000 rows, drops the tree at row `+0x20` of each other row, and keeps the allocation capacity.

Result layout: tag or code capacity at `+0`. `0x8000000000000000` is `needToTrade` with the f64 at `+8`. `0x8000000000000001` is `needToCreateCode`. Any other value is `ready`: code at `+0`, `+8`, `+0x10`, row vector at `+0x18`, `+0x20`, `+0x28`, `nReferrals` at `+0x30`.

Row layout, from the serializer `0x22cec10` and `0x23d17c0`: `+0` `cumVlm`, `+8` `cumRewardedFeesSinceReferred`, `+0x10` `cumFeesRewardedToReferrer`, `+0x18` `timeJoined`, `+0x20` `tokenToState` (tree, by inference from the drop at `+0x20`), `+0x38` `user`.

### Folders

`0x251bf90` takes a slice of 16-byte items, each holding a pointer to an address, and a folder with a vector and a context. State is two loads from the context. It returns early when the root at state `+0x6d8` is 0. Otherwise each address found in that tree (the same key layout as step 1) goes to `0x2a2b0a0` with tracker state `+0x5d0`, spot context state `+0x90` and flag 0 (`xor r8d, r8d` pinned at `0x251c1aa`). A result tag of `0x8000000000000002` skips the row, the niche of an `Option` that `0x2a2b0a0` never returns. Others push a `0x50`-byte row: address at `+0`, tag at `+0x18`, then the 6 result words at `+0x20`. `0x251c680` is the same with `+0x1158` and tracker `+0x1050` (the `+0xa80` shape), flag 0 pinned at `0x251c89a`.

Those are the only 2 users of the slot. So the 5000 cap of step 7 and `0x2a39bd0` are reached by no call in this binary that passes a non-zero flag: both pass 0. The cap branch is present and evaluated, and has no caller that turns it on.

### Approved builder list

`0x2a2b5f0` returns an empty vector (capacity 0, pointer 1) when tracker `+0xd8` is 0 or the user has no row. Otherwise it allocates length x 20 bytes, with a checked multiply, and copies the keys of the tree at item end `-0x50`, `-0x48`, `-0x40` in key order. The node layout has keys at `+0x60`, parent `+0`, index `+0x13c`, count `+0x13e`, children `+0x140`. Item end `-0x50` is row `+0x98`, the tree of `fees-builder-gate-94`, so by inference this is the list of approved builders of one user.

## Implementation and comparison

Rust: not yet implemented. Comparison is between the decoded instructions, interpreted in Python, and a separate closed-form model in the tool.

- 384 vectors, 0 mismatches. Records are compared after each run: unwritten result bytes keep their pattern, and rows are compared byte for byte.
- Hash tables use the real group layout with clashing control bytes, tombstones and probes over several groups. B-trees use the real node layouts, up to height 17 through thin spines, so all unrolled descents run. Parent links are real.
- 877 byte mutants over the 11 subjects: 837 killed, 40 equivalent with reasons in `mutations.tsv` and `evidence.json`, 0 unclassified.
- 64 unit tests pass, with negative controls for the digest, a corrupted binary, a range outside any FDE, pins, the threshold, the shortfall base, the divisor, the default, the cap, the count store, the short sort bound, the sort compare, the niche and strides.

## Results and limitations

- Instructions executed: 1576 of 1740. The rest are padding and the ranges in `evidence.json` `unexecuted`: unwind landing pads, code after calls that do not return, and tests that cannot fail with a valid iterator.
- `0x2a2a9f0` is a stub that writes a chosen row, because #811 lists that body. By hand reading only, it divides by 100 for `cumVlm` and by 10 to the token wei decimals for the two fee words: not evaluated here.
- `0x2a40430` is a stub that applies the same order; the comparator inside the long sort is not evaluated. `0x2a39350` is a stub, so the hash is outside this result.
- A vector with a stubbed walker supplies the rows of the cap group, so 5000 rows did not walk a real tree.
- Which view passes a non-zero flag is unknown: none by these 2 slot users. A one-off scan for rel32 calls, lea and RELATIVE entries found no other reference to the function; `call-sites.tsv` keeps only the slot and call rows. `0x27dca30` and `0x258a0b0` hold a lock, read a clock and are not evaluated.
- The folder callers `0x228dcb0`, `0x228bf00` and the drivers above them are listed in `call-sites.tsv` and not evaluated. The name of the file or view they serve is not shown here.
- No state was read: no real referrer, code or row is claimed. #115 is not checked. `reference-diff.tsv` lists 2 rows.

Next question: who reads tracker `+0xf0` (`unrewarded_users`, written by vote raw `0x2f`), and does that set stop any referrer credit in the fill path?
