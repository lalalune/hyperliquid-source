# fees: the per-token ledger of one fill in node #94

- Component ID: `fees` (first task: maker/taker fee formulas and time-window rollover; this packet fixes where the fee record of a
  fill is stored, the rollover stays open).
- Target release and full SHA-256: hl-node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` /
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only, nothing copied).
- Claim status: observation for bytes, decoded instructions, evaluated outcomes, serde keys and offsets; inference where marked;
  unresolved items are listed at the end.
- Scope included: `0x3745a60` in full, with its bucket path `0x3596da0` and `0x379a610`; the field keys of serializers `0x37497d0`
  and `0x23382e0`; the record each of the two callers passes. Scope excluded: the hash `0x399c7a0`, the B-tree helpers `0x33bcd10`,
  `0x33bc720`, `0x33c0590` beyond their handles, leaf splits, the table reserve `0x357d310`, the settlement family `0x26ff460`,
  `0x4ce8b40`, `0x4ce9670`, and node #115.

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 tools/fees_fill_ledger.py --out research/work-items/fees-fill-ledger-94
python3 -m unittest tests.test_fees_fill_ledger
(cd research/work-items/fees-fill-ledger-94 && sha256sum -c MANIFEST.sha256)
# optional, for a human reader only; no evidence file uses this
objdump -d -M intel --start-address=0x3745a60 --stop-address=0x37463e7 artifacts/node/94/hl-node
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input SHA-256 first and
fails on any other file. It starts no external program, so no binutils version can change its output. Sections and FDEs come from
`tools/elf_index.py` and `tools/fde_extents.py`. It does not run the node or visor: decoded instructions are interpreted in
Python. A full run takes about 100 seconds and writes `evidence.json`, `vectors.tsv`, `mutations.tsv`, `instructions.tsv` and
`reference-diff.tsv`.

## Evidence

All addresses are ELF virtual addresses. Function ranges come from `.eh_frame`, and the decoder must land on each FDE end
(`evidence.json`, `functions`).

### Where the code is

| Function | FDE range | Instructions | Role here |
|---|---|---|---|
| `0x3745a60` | `0x3745a60..0x37463e7` | 540 | store one fee record |
| `0x3596da0` | `0x3596da0..0x3596f00` | 75 | find or insert the bucket of an address |
| `0x379a610` | `0x379a610..0x379a74e` | 87 | probe for that bucket, reserve when no slot is left |

`0x3745a60` has two direct calls and no slot: `0x37159dc` in `0x37153f0` (perp) and `0x3730460` in `0x372faa0` (spot) (`evidence.json`,
`callers`). The arguments are `(tracker, user, key, record)`.

### The tracker

`0x23382e0` writes the serde fields of the `FeeTracker` struct, whose name and element count are the string
`struct FeeTracker with 10 elements`. The tool reads each name and offset at a pinned instruction, or in the callee for two of them
(`evidence.json`, `fee_tracker_fields`):

| Offset | Field | Offset | Field |
|---|---|---|---|
| `+0x00` | `fee_schedule` | `+0x138` | `referral_bucket_millis` |
| `+0xc0` | `user_states` | `+0x140` | `total_fees_collected` |
| `+0xf0` | `unrewarded_users` | `+0x148` | `total_spot_fees_collected` |
| `+0x108` | `referrer_states` | `+0x150` | `collected_builder_fees` |
| `+0x120` | `code_to_referrer` | `+0x168` | `trials_disabled` |

The earlier fee packets' `ctx` has the same shape: table at `+0xc0`, mask `+0xc8`, items `+0xd8`, 0xe8-byte buckets, and the trial writer
`0x3744020` returns status 0x138 when byte `+0x168` is set. That the serialized struct and `ctx` are one object is an inference from those
offsets. On that reading, the hash table is `user_states`.

### The six-word value

Each bucket holds a B-tree map at end `-0x38` (root), `-0x30` (height), `-0x28` (length), with a 64-bit key. Its values are 0x30 bytes.
`0x37497d0` serializes one value. It loads six words from `+0x00` to `+0x28` and writes each non-zero word under a one-letter key
(`evidence.json`, `token_value_keys`):

| Offset | Key | Written here |
|---|---|---|
| `+0x00` | `V` | not here: the caller adds the scaled volume at `0x3715802` (perp) and `0x37302c9` (spot) |
| `+0x08` | `U` | referrer and builder credit |
| `+0x10` | `C` | not written by this function |
| `+0x18` | `r` | referrer amount, on the paying user |
| `+0x20` | `F` | gross less rebate less extra, on the paying user |
| `+0x28` | `T` | extra, on the paying user |

In `.rodata` the letters `V`, `U`, `C` are followed directly by `token_to_state` (`0x598577`).

### The record

The caller builds this on its stack (`evidence.json`, `pinned`, for the lines the table rests on):

| Record | Meaning | Perp source | Spot source |
|---|---|---|---|
| `+0x00` | referrer tag | low bit of `[side+0x58]` | low bit of `[side+0x60]` |
| `+0x08` | referrer amount | `[side+0x60] * 100` | `[side+0x68]` |
| `+0x10` | referrer address | `side+0x68` | `side+0x70` |
| `+0x28` | builder tag | low byte of `[side+0x80]` is not 0 | low byte of `[side+0x88]` is not 0 |
| `+0x30` | builder amount | `[side+0x88] * 100` | `[side+0x90]` |
| `+0x38` | builder address | `side+0x90` | `side+0x98` |
| `+0x50` | gross | `[side+0xa8] * 100` | `[side+0xb0]` |
| `+0x58` | rebate | `[side+0xb0] * 100` | `[side+0xb8]` |
| `+0x60` | extra | `[side+0xb8] * 100` | `[side+0xc0]` |

Offsets in the perp column are those of the side block in the fee packet `fees-trade-fee-94`. In spot, `side` is `record` or
`record + 0xf8` (`0x3730030..0x3730041`) and each offset is the perp one plus 8. Both callers skip the call when the first tag word is
2. Spot uses no multiplier. An address and its amount are only loaded when the tag says so, so the other record words can be stale.
The key is `[state+0x50]` in perp, and in spot the word at `+8` of a 32-byte pair entry (`0x3730094`).

### Formula

`add` saturates at `u64::MAX` and calls the recorder at ``l1/src/qtys/mod.rs:831:1``. `less` floors at 0 and calls the recorder at
``l1/src/qtys/impl_wei.rs:6:1``. `value(a)` finds or creates the bucket of `a`, then finds or creates the zero value under `key`.

```text
v = value(user)
add(v.T, extra)
if low 32 bits of the referrer tag == 1:
    add(v.F, less(less(gross, rebate), extra))
    add(v.r, referrer_amount)
    add(value(referrer).U, referrer_amount)
if low byte of the builder tag != 0 and builder_amount != 0:
    add(value(builder).U, builder_amount)
    add(collected_builder_fees[builder][key], builder_amount)
```

So `V` and `C` are untouched, a fill with no referrer changes only `T`, and the builder step changes no word of the paying user. A
referrer amount of 0 still creates the referrer's bucket and value, and a builder amount of 0 creates nothing. When the referrer or
builder is the user, the same value is added to twice, and when the bucket is missing it is created in user, referrer, builder order.

`collected_builder_fees` is a map from 20-byte address to a map from `u64` to `u64`. Its node shapes are read from the search loops:
outer keys at `+0x110`, length `+0x1ee`, children `+0x1f0`, values at `+8` with a 0x18 stride; inner keys at `+8`, length `+0xba`,
children `+0xc0`.

### Bucket insert

A new bucket gets its control byte twice, the key, zero at end `-0xd0` (trial tag), `-0x50` and `-0x38` (roots), `-0x28` (length),
`-0x20` and `-0x1c`, and `items` grows by one. The inline copy in `0x3745a60` (for the referrer) and `0x3596da0` do the same. The
reserve at `0x37463af` and `0x379a743` runs when growth left is 0, before the slot is chosen.

### Examples

From `evidence.json`, `examples`, with key `0x168` and a user value of `V=101 U=202 C=303 r=404 F=505 T=606`:

| Case | User after | Other after |
|---|---|---|
| gross 1000, extra 30 | `T=636` | |
| referrer 100, gross 1000, rebate 50, extra 30 | `r=504 F=1425 T=636` | referrer value `U=100` |
| builder 25, gross 1000, extra 30 | `T=636` | builder value `U=25`, map entry 25 |
| referrer 100 is the user, gross 1000, extra 30 | `U=302 r=504 F=1475 T=636` | |

## Implementation and comparison

Implementation: not yet implemented. `tools/fees_fill_ledger.py` holds a closed-form model for test use only. No Rust build, so no
two-build result and no normalization mask.

Method: a table decoder gives the instructions and a Python evaluator runs them. Memory is strict: reading a byte nobody set is a
fault, apart from four listed instructions that copy padding or an unused map height (`LOOSE` in the tool). Real hashbrown control
bytes and real node shapes are built for each vector, so every probe and search loop runs. Stubs spoil caller-saved registers.
The B-tree entry stubs read back the handle the search built, refuse a handle above a leaf and refuse a key out of order, and
insert into real node memory, so a second lookup in the same call sees the first insert. Callee-saved registers are checked on return.
The model also computes each new bucket's slot, the reserve calls and the final growth left from hashbrown's rules, and the run
must match them.

| Measure | Value |
|---|---|
| vectors | 1015, 0 mismatches |
| groups | shapes 128, plain 240, tags 48, subtraction 28, saturation 73, alias 10, builder 134, probe 32, collision 22, random 300 |
| instructions executed | 700 of 702; the other 2 are padding `nop`s in `0x3745a60` |
| mutants | 99: 99 killed, 0 equivalent, on 463 sampled vectors |

The mutants are every conditional jump, conditional move and `set` (70), the disp8 of each record or value field access (27), and the
two referrer tag compares (2). The first flip survey killed 93 of 97: the four survivors showed that the comparison did not check
growth left or the slot of a new bucket, so the independent slot model was added rather than calling them equivalent.

As a one-off authoring check, not part of the evidence, GNU objdump 2.42 was read by hand for all three functions.

`reference-diff.tsv` compares with the reference tree. `apply_builder_vault_fee_split` in `l1/fees/compute.rs` is the nearest model.
It has the same three-step order and subtraction, and it differs in the shape of the state, in the second amount, in zero amounts,
in the recorder calls on underflow, and in the second map key, which it calls a day.

## Results and limitations

Inferences, not observations:

- The 64-bit key is a token index. `token_to_state` follows the keys in `.rodata`, the JSON view at `0x23d17c0` writes `tokenToState`,
  the spot key is a pair table word and not a date, and `0x3743020` sums `V` over the whole map, which fits a per-token split better
  than a day split. No byte names `[state+0x50]`.
- `U` means unclaimed and `C` claimed. Only `U` is credited here. No claim path was read.
- `V`, `F` and `r` are the values behind `cumVlm`, `cumRewardedFeesSinceReferred` and `cumFeesRewardedToReferrer`. The view
  serializer `0x22ce6b0` writes those three names from a struct of three words, and the function that fills it was not read.
- The amounts are in 1e-8 units, since perp multiplies by 100 and spot does not, and the recorder locations are in the `Wei` file.
- With `V` from perp being `notional * rate / 10000` (open packet `fees-unit-conversion-94`), a 1e-6 notional gives `V` in cents.
  The limits in `fees-trade-fee-94` would then read 2.5e9 = 25M and 1e11 = 1B in dollars. This is arithmetic on an inferred unit.
- `T` is the extra that a fee trial charges above its rates. Its name rests on the letter and on `extra` in `fees-trade-fee-94`.

Unresolved:

- Who writes `C`, and what clears `U`.
- `0x26ff460` and `0x4ce8b40`, read by hand at their `0x33bcd10` calls, read `T`, zero it, in one mode add it to `U` (pinned at `0x26ffda4`
  and `0x26ffdac`), and store a 32-bit word at entry `+0xb0`, which the trial writer `0x3744020` reads as the base of a 90-day cooldown.
  `0x4ce8b40` also has a 14-step loop over dates. `0x4ce9670` is a sibling of the same size and was not read. This looks like the daily
  rollover. It is not evaluated here.
- Leaf splits are outside the stubs. A vector that needs one is refused, so no result rests on a split.
- The helpers are stubs, and the hash stands in for `0x399c7a0`, so slot numbers are from test hashes.
- `total_fees_collected` and `total_spot_fees_collected` are not written here.
- Mutation kills are from a sampled vector set. Unsampled vectors could only add kills.

No progress gate is requested.

Next question: when the rollover family runs, how does it choose between moving `T` to `U` and dropping it, and what date does it store
at entry `+0xb0`?
