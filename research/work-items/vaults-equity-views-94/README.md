# vaults: node #94 vault equity read path: total, user equity, userVaultEquities and vaultSummaries rows

This packet shows how a vault's total, a user's share of it and the two vault views are computed, including that a parent adds each child's equity with
a saturating sum, that a user's value floors at 0 while `tvl` keeps a negative total, and that zero equity rows drop out of `userVaultEquities`,
so the read side of `l1/vault` can now be written from the bytes with its exact casts, row layouts and JSON keys.

- Component ID: vaults
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository 1f8c67c; reference `references/can1357-hl` used as a label source only
- Claim status: observation for pins, layouts, JSON keys and evaluated results; inference where marked; unresolved items are listed at the end
- Scope included: total 0x3957bc0, user equity 0x3957e90, fold 0x26b1430 with wrappers 0x25677f0 and 0x2570c00, iterator 0x27e1210, list builder 0x25813f0, summary loop 0x26b2b00 and row 0x2a35f40, serializers 0x2a367d0 and 0x2a36180; pins in the queries 0x27cf850 and 0x27ceff0
- Scope excluded: account equity 0x3955e80 and lockup reader 0x39597b0 (our open PR #873), consumer 0x2727f30, precompile closure 0x3249a20, `leadingVaults`, the HLP snapshot (companion packet `vaults-withdraw-guards-94`)

## Reproduce

From the repository root, Python 3 standard library only, no external programs:

```sh
python3 tools/vault_equity_views.py --out research/work-items/vaults-equity-views-94
python3 -m unittest tests.test_vault_equity_views
```

The tool checks the binary SHA-256, reads ELF bytes, and imports `tools/elf_index.py` and `tools/fde_extents.py` for
sections and FDEs. It never runs the binary. It writes evidence.json, functions.tsv, stubs.tsv, callers.tsv, pins.tsv, layout.tsv,
locations.tsv, json-keys.tsv, cases.tsv and outcomes.tsv. All contents are deterministic.

## Evidence

Addresses are ELF virtual addresses. Extents are FDE ranges (`functions.tsv`), 13 functions and 9,590 bytes. Instruction
text in `pins.tsv` comes from the small decoder inside the tool, each of the 49 rows is compared with a frozen expected string, and an unknown
encoding raises an error. `layout.tsv` ties 14 field offsets to one decoded access each.

### Vault value

Rows are 0xb0 bytes in a B-tree map keyed by 20-byte address: keys at node +0x798, values at +0, parent +0x790, parent index +0x874, length +0x876, edges +0x878.

| Offset | Field |
| --- | --- |
| +0x00 | relationship tag: 0 normal, 1 child, 2 parent, as named in the lifecycle packet |
| +0x08, +0x18 | child set root and length: keys of 20 bytes at node +0x08, length +0xe6, edges +0xe8 |
| +0x28, +0x30 | name pointer and length |
| +0x50 | follower map root: keys at node +0x218, 0x30-byte values at +0, length +0x2f6, edges +0x2f8 |
| +0x78 | creation time: date word, seconds, nanoseconds |
| +0x84 | vault address |
| +0x98 | leader |
| +0xac | closed byte |

### Total and user equity

```text
total(v) = equity(v.address)
if tag >= 2 and the child set is not empty:
    for child in key order: total = saturating_add(total, equity(child))
                            on overflow call the recorder and go on

user_equity(v, u):
    u not in followers: return 0, with no equity call
    x = follower.share * (total(v) as f64)
    non-finite: 0
    r = clamp(x) to the i64 range, truncated, i64::MAX above 9223372036854774784.0
    return max(r, 0)
```

0x3957e90 inlines the total walk, and it tests `tag < 2` where 0x3957bc0 tests `tag <= 1`. `equity` is 0x3955e80 with the context (clearinghouse 0, frame +0x80, frame +0x498).
The saturating walk records with Location `l1/src/qtys/mod.rs:830:1`. A later child can move a saturated sum back: `cases.tsv` shows i64::MAX + 1 - 5.

### userVaultEquities

0x27cf850 builds an iterator over the vault map in the state frame (state +0x570 + 0x1350) and calls 0x25813f0.
For each vault in key order:

1. no clearinghouse: panic at clearinghouses.rs:11:29, on the first vault only when the map is not empty
2. `e = user_equity`, and `e == 0` skips the row
3. lockup end time from 0x39597b0
4. row of 0x28 bytes: `equity = e as f64 / 1e6`, `lockedUntilTimestamp = ms(time)`, then the vault address

`ms` is the chrono date to Unix milliseconds in integer arithmetic, clamped at 0. The first allocation holds 4 rows.
The serializer order is vaultAddress, equity, lockedUntilTimestamp (`json-keys.tsv`).

### vaultSummaries

0x27ceff0 allocates one 0x78-byte row per vault and calls 0x26b2b00, which calls 0x2a35f40 for every vault. No address compare appears on this
path, although the reference has a `leader` argument.

| Row offset | JSON key | Source |
| --- | --- | --- |
| +0x20 | name | clone of the vault name, capacity = length |
| +0x48 | vaultAddress | vault +0x84 |
| +0x5c | leader | vault +0x98 |
| +0x38 | tvl | total as f64 / 1e6, sign kept |
| +0x70 | isClosed | vault +0xac |
| +0x00 | relationship | tag; tag 2 and up also clone the child set into +0x08 to +0x18 |
| +0x40 | createTimeMillis | ms(vault +0x78), clamped at 0 |

With an empty child set the root and length words are 0, and the height word is not written.

### Fold

0x26b1430 writes `user_equity` for each vault, in key order, into a Vec with a row for every vault, zeros included. The wrappers 0x25677f0 and 0x2570c00 allocate it. By
hand reading, 0x2727f30 scales each value by clearinghouse +0x2a0, clamps and adds.

### Evaluation

The tool runs each body in Python over the real instruction bytes, nested calls included, and compares the result with a plain model: 1,200 vectors with
0 disagreements and 18 distinct outcomes (`outcomes.tsv`), plus 12 named scenarios in `cases.tsv`. Fixtures build real B-trees up to height 2
with parent links, so the iterators walk real ascents. `stubs.tsv` lists the 10 replaced calls. Stubs overwrite caller-saved registers and all xmm registers.

### Inferences

- `equity` is the account value of an address, and share is the fraction held by a follower, from the row shape and the lifecycle packet.
- The f64 division by 1e6 fits the 6-decimal USD amounts of the JSON output.

### Reference comparison

| Reference text | Bytes |
| --- | --- |
| `vault_summaries(leader)` | no address compare in 0x27ceff0, 0x26b2b00 or 0x2a35f40; every vault gets a row |
| `total_vault_ntl`, `participant_equity_ntl` as a single sum | tag gate, ordered child walk, saturating with a recorder call |
| `trunc_saturating_i64` | same clamp ends, non-finite gives 0, then a floor at 0 that the view relies on |
| `UserVaultEquity` with `vault_address`, `equity`, `locked_until_timestamp` | same fields, with zero rows dropped before the list |

## Implementation and comparison

not yet implemented. No Rust was written. The formulas above are readings of the bytes, checked over the listed vectors.
They are not a claim of binary equivalence.

## Results and limitations

Passed: 49 pins, 14 layout rows, 10 JSON key rows, 13 functions, 10 stubs, 6 Location records, 1,200 vectors with 0 disagreements and
12 named scenarios. `tests/test_vault_equity_views.py` runs 30 tests, including 8 negative controls (wrong binary hash, address outside file-backed
sections, changed pin byte, changed layout operand, changed key string, unknown encoding, unmodelled call, non-FDE start) and 14 one-edit binary mutants, each of which the models catch.

Limits:

- `equity` and the lockup reader are stubs, so no real account or lockup value enters a vector.
- The two queries are pinned, not evaluated: the read lock at state +0x568 and their timers are not modelled.
- `leader` may be filtered above 0x27ceff0. This packet shows only that these three functions do not filter.
- The serializers are read through their key table. The value writers are not run, so number formats are out of scope.
- 0x2727f30, the HyperEVM closure 0x3249a20 and `leadingVaults` read these helpers and are not covered.

Next question: what does 0x2727f30 use the scaled sum of a user's vault equity for, and which callers of 0x251cdd0 reach it?
