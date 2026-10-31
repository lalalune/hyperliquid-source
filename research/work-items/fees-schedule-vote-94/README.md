# fees: JSON wire form of the node #94 FeeSchedule vote

This packet settles what a rebuilt node must parse for a `FeeSchedule` governance vote: not the nine `u64` words of the
reference, but a JSON text of at most 10000 bytes that decodes into nine optional parts, with exact keys, array forms,
null handling and refusal order, so a Rust `Deserialize` for the fee schedule patch can now be written from evidence.

- Component ID: `fees` (rate tables and their updates).
- Target release and full SHA-256: hl-node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only).
- Claim status: observation for bytes, decoded instructions and evaluated outcomes; inference where marked; unresolved
  items are listed at the end.
- Scope included: decoder `0x1b2c4e0`, top visitor `0x1cfe930`, key identifier `0x1e6e3d0`, six nested visitors, eight
  option wrappers, and the same outcomes through the second decoder `0x43a3c90`. Scope excluded: `0x3744550` (update, in
  `fees-schedule-admission-94`, which lists schedule decoding as out of scope), the rate grid, and the rollover call after
  the update.

## Reproduce

```sh
python3 tools/fees_schedule_vote.py --out research/work-items/fees-schedule-vote-94
python3 -m unittest tests.test_fees_schedule_vote
(cd research/work-items/fees-schedule-vote-94 && sha256sum -c MANIFEST.sha256)
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input SHA-256
first and fails on any other file. It starts no external program, so no binutils version can change its output. Sections
and FDEs come from `tools/elf_index.py` and `tools/fde_extents.py`. It does not run the node or visor: decoded instructions
are interpreted in Python. A full run took about 190 seconds on a loaded machine.

## Evidence

All addresses are ELF virtual addresses. Function ranges come from `.eh_frame`, and the decoder must land on each FDE end.

### From the vote to the decoder (read from the listing, pinned in `evidence.json`)

Vote arm raw `0x12` starts at `0x2355f7f` (jump table `0x3dd1b8`, index raw minus `0x12`). The action holds a byte `Vec`:

| Step | Site | Effect |
|---|---|---|
| length gate | `0x2355f9a` | above 10000 bytes: tag `0x143` |
| reader setup | `0x2359c6f` | slice reader over the bytes |
| decode | `0x2359cb1`, direct call of `0x1b2c4e0`, its only caller | failure: tag `0xbd` |
| update | `0x235acd9`, slot `0x5773e40` to `0x3744550` | patch goes to the schedule update |
| refresh | `0x235acf1`, `0x235acff` | clock read `0x3c0c870`, then `0x26ff460` |

The copies `0x4caa870` and `0x4cb3200` hold the same arm with decoder `0x43a3c90` (call at `0x4cae559` in the first).
The arm itself is read from the listing here, not evaluated. The decoders are evaluated.

### Schema

`schedule-schema.tsv` is checked against the key bytes in `.rodata`.

- Top keys are camelCase, nested keys snake_case. Stake row keys are `boms` and `discount`, not the view names
  `bpsOfMaxSupply` and `discount`.
- Every top part is optional, `{}` is a valid empty patch, and `null` equals an absent part except that a later repeat is
  then a duplicate field.
- Every struct also accepts its positional array form: `[rates, tiers, referralDiscount, referrerKeep, destination,
  extraDestinationFractions, stakeDiscountTiers, weighSpotVolumeDouble, alignedQuoteTokenConfig]`. Too few items give
  invalid length; too many give trailing characters.
- `rates` is an array only: an object is a type error at the top and in a vip row.
- Unknown keys are refused at the top level and skipped in all nested structs.
- `staking_keep_frac_for_referrer` is the only nested field with a default: 0.0, also in the positional form.
- `ntl_cutoff` is an integer in `0..=u64::MAX`. A negative value is refused by the text `invalid value {} for NtlPriv when
  visiting i64`, a float by a type error, and a one item array is accepted as the value.
- `destination` takes an optional lower case `0x`, hex digits of either case and exactly 20 bytes.
- `extraDestinationFractions` is an object or an array of pairs, stored as a B-tree sorted by key bytes. Equal keys are
  refused with `duplicate key`, reported only after the whole container has been read.
- f64 values use the reader's plain decimal rule, not exact rounding: the model reproduces every number vector with
  `significand` times or over a power of ten.

### Patch offsets

| Part | Present when | Value |
|---|---|---|
| rates | `+0x00` bit 0 | `+0x08..+0x27`, order cross, add, spotCross, spotAdd |
| referralDiscount | `+0x28` non-zero | `+0x30` |
| referrerKeep | `+0x38` non-zero | `+0x40` |
| extraDestinationFractions | `+0x48` bit 0 | root `+0x50`, height `+0x58`, length `+0x60` |
| alignedQuoteTokenConfig | `+0x68` bit 0 | `+0x70` cross_scale, `+0x78` add_rebate_scale, `+0x80` vlm_contribution_scale |
| tiers | `+0x88` not `i64::MIN` | vip `Vec` `+0x88`, stride `0x30`; mm `Vec` `+0xa0`, stride `0x10` |
| stakeDiscountTiers | `+0xb8` not `i64::MIN` | `Vec`, stride `0x10` |
| destination | `+0xd0` bit 0 | `+0xd1..+0xe4` |
| weighSpotVolumeDouble | `+0xe5` not 2 | byte |

The vip row is four f64 rates, `ntl_cutoff` at `+0x20`, keep share at `+0x28`. Together with the update table of
`fees-schedule-admission-94` this names every patch part of that packet; its `+0x68` part (three words) is the aligned
quote row, and its `+0x38` part is `referrerKeep`.

### Evaluation

| Metric | Value |
|---|---|
| Vectors | 1251 |
| Mismatches | 0 |
| Other functions interpreted | 199 |
| Executed / total 0x1b2c4e0 | 62 / 76 |
| Executed / total 0x1c55870 | 392 / 517 |
| Executed / total 0x1c5e220 | 360 / 492 |
| Executed / total 0x1c89bd0 | 333 / 455 |
| Executed / total 0x1cc48f0 | 424 / 541 |
| Executed / total 0x1cd0790 | 321 / 464 |
| Executed / total 0x1cfcdf0 | 533 / 800 |
| Executed / total 0x1cfe930 | 1340 / 1787 |
| Executed / total 0x1e6e3d0 | 121 / 121 |
| Executed / total 0x251eee0 | 83 / 96 |
| Executed / total 0x251f690 | 85 / 98 |
| Executed / total 0x2520f40 | 84 / 88 |
| Executed / total 0x2522870 | 81 / 94 |
| Executed / total 0x2523800 | 81 / 85 |
| Executed / total 0x2524090 | 79 / 92 |
| Executed / total 0x25259d0 | 79 / 92 |
| Executed / total 0x2526910 | 79 / 92 |
| Outcome: duplicate field | 50 |
| Outcome: eof string | 69 |
| Outcome: expected ident | 58 |
| Outcome: expected value | 67 |
| Outcome: invalid length | 54 |
| Outcome: invalid type | 288 |
| Outcome: missing field | 124 |
| Outcome: patch 1 | 219 |
| Outcome: patch 2 | 28 |
| Outcome: recursion limit | 24 |
| Outcome: trailing comma | 24 |
| Outcome: unknown field | 108 |

Each vector runs the real bytes from the decoder entry, with the JSON reader and number code interpreted. Stubs: allocator
family, memory copy, memcmp, `0x1344760` (text format) and `0x4ebc460` (message error builder). The stubs track every heap
block: after a rejection only the error box may stay live, after success only the blocks the patch owns, so a leak or a
double free in a partial build fails the vector. The result is compared with `model` in the tool, a separate reader written
from the field table: patch fields, or error kind, line and column.

## Implementation and comparison

Not yet implemented. No Rust type is added here. The comparison is the byte evaluator against the separate model.

## Results and limitations

- 1251 vectors, 0 mismatches between the bytes and the model.
- `reference-diff.tsv`: the reference `FeeSchedule` struct of nine `u64` words does not match this decoder.
- Mutation is a sample: one site in 6, at most 25 reaching vectors per site. 383 of 588 mutants were killed, and
  205 survived and are listed as `survived` in `mutations.tsv`, not proved equivalent.
- `unexecuted.tsv` lists every unreached range. They are unwind landing pads, allocation failure arms and error joins no
  vector reached; they were not classified one by one.
- Vector counts were cut to fit the run: the second decoder sees one vector in 13.
- Numbers with an exponent above `i32` range are not run: that block has no FDE start in the closure. A bad hex digit in an
  address is seen only as a refusal, since text rendering is a stub. One manual probe, `0102030405060708090a b0c0...`, a
  space inside 40 characters, was accepted with shifted bytes; it is not in the vectors and not modelled.
- The field meanings (`referrerKeep` as referrer share and so on) come from names and the admission packet, so they are
  inference. Non-ASCII text and lone surrogate escapes are not covered.
- The vote arm is pinned and read, not evaluated, and the rollover call after the update is not followed.

Next question: does the second decoder `0x43a3c90` differ anywhere, and which reader feeds it?
