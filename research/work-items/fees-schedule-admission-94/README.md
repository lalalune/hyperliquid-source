# fees: how node #94 updates and admits a fee schedule

- Component ID: `fees` (first task: maker/taker fee formulas; this packet fixes which rate tables can exist at all).
- Target release and full SHA-256: hl-node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` /
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only).
- Claim status: observation for bytes, decoded instructions and evaluated outcomes; inference where marked;
  unresolved items are listed at the end.
- Scope included: `0x3744550` (update), `0x3c02dc0` (admission ladder), `0x3c05c30` (float floors), and the two
  real iterators they call. Scope excluded: the rate grid behind `0x3404030`, the code that reads a rate at trade
  time, schedule decoding, and non-finite float inputs.

## Reproduce

```sh
python3 tools/fees_schedule_admission.py --out research/work-items/fees-schedule-admission-94
python3 -m unittest tests.test_fees_schedule_admission
(cd research/work-items/fees-schedule-admission-94 && sha256sum -c MANIFEST.sha256)
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input
SHA-256 first and fails on any other file. It starts no external program, so no binutils version can change its
output. Sections and FDEs come from `tools/elf_index.py` and `tools/fde_extents.py`. It does not run the node or
visor: decoded instructions are interpreted in Python. A full run takes about five minutes, most of it the branch survey.

## Evidence

All addresses are ELF virtual addresses. Function ranges come from `.eh_frame`, and the decoder must land on each
FDE end (`evidence.json`, `functions`).

### Where the code is

| Function | Range | Instructions | Role |
|---|---|---|---|
| `0x3744550` | `..0x3744ea2` | 491 | update: merges a patch into a copy, validates, swaps |
| `0x3c02dc0` | `..0x3c042ee` | 1099 | admission ladder, one direct caller at `0x3744a64` |
| `0x3c05c30` | `..0x3c06090` | 203 | float floors, two calls at `0x3c03c93` and `0x3c03d51` |

`0x3744550` has no direct call. Slot `0x5773e40` holds it by a RELATIVE relocation and three sites call through
the slot: `0x235acd9`, `0x4caf5e4`, `0x4cb7f74`. The tag written on rejection is `0x9d`; the Display table at
`0x59a8d0` sends it to the arm at `0x38019d2`, which prints `Invalid fees`. Acceptance writes `0x186`
(`evidence.json`, `caller`).

### Schedule layout

`fields.tsv` takes names from serializer bytes: each row is a `lea`/`add` of an offset, then the name string and
its length. They give `+0x48 cross`, `+0x50 add`, `+0x58 spotCross`, `+0x60 spotAdd`, `+0x68 referralDiscount`,
`+0x30 stakingDiscountTiers`, `makerFractionCutoff` and `add` for an mm row, and `bpsOfMaxSupply` and `discount` for
a stake row. The ladder reads the same offsets with the same strides; that the serializer works on this same struct
is an inference. The other rows are readings of the ladder and say so.

| Offset | Content |
|---|---|
| `+0x00` | vip `Vec`, stride `0x30`: four f64, u64 at `+0x20`, f64 at `+0x28` |
| `+0x18` | mm `Vec`, stride `0x10`: cutoff, add |
| `+0x30` | stake `Vec`, stride `0x10`: bps, discount |
| `+0x48..+0x60` | four f64 base rates |
| `+0x68`, `+0x70` | referral discount, an unnamed f64 in [0, 1] |
| `+0x78` | `BTreeMap<[u8; 20], f64>`, node layout read by `0x330fed0` |
| `+0x90..+0xa0` | three f64 |
| `+0xa8`, `+0xbc` | 20 bytes and one byte, never read by the ladder |

### Admission order

The ladder first builds lists: each rate list is the base rate followed by the vip column, the two mm lists are a
base add rate (`+0x50`, `+0x60`) followed by the same mm add column, the ntl list starts at 0, the cutoff list at
0.0, and the `+0x28` list at 1.0. Then it runs 28 checks in the fixed order of `checks.tsv`:

1. six rate lists must not rise (equal neighbours pass);
2. ntl and maker cutoffs must rise strictly;
3. the `+0x28` list must not rise;
4. stake rows must rise strictly in both columns, then the last row is capped at bps 5.0 and discount 0.5;
5. `+0x70` and the referral discount must lie in [0, 1];
6. the map values, summed from `-0.0`, must not exceed 1.0;
7. `+0x90 <= 1.0`, `+0x98 >= 1.0`, `+0xa0 >= 1.0`;
8. `0x3c05c30` for the perp set, then for the spot set;
9. every cross rate in [0, 0.001], then every add rate in [-0.001, 0.001].

The range checks of step 9 run after the floors and the grid, not before. Evaluated order, not source order, is
what `vectors.tsv` records: for a rejected vector, `first_exit` is the instruction that left for the failure path.

Twelve of the 28 exits go to `0x3c03dd6` directly. The other 16, the first 13 and the three aligned checks, pass
through `0x3c03dc8`, which calls a one-time initialiser when the word at `0x577ab98` is non-zero. Both return false.
The vectors run both states of the word.

### Float floors

`0x3c05c30` works on the lowest rates, because the lists do not rise:

```text
m        = min(last add, last mm add)
add_low  = m < 0 ? word98 * m : m
cross_low = word90 * last cross
net      = (1 - keep) * ((1 - last discount) * ((1 - referral) * cross_low))
keep_net = (1 - keep) * ((1 - referral) * cross_low)
```

It fails when `5e-06` is above any of eight values, in this order: `net + add_low`, then
`fma(net, m, add_low * m)` for m = 0.2 and 6.0, then `fma(keep_net, m, add_low * m)` for m = 0.1, 6.0 and 0.2,
then `keep_net + add_low`, then `fma(net, 0.1, add_low * 0.1)`. The call slot `0x576f6e0` dispatches on CPU
features; one target starts with the bytes of `vfmadd213sd xmm0, xmm1, xmm2`, so the stub is an exact fused
multiply-add (`evidence.json`, `fused_multiply_add`). After the floors the function calls `0x3404030` with four
scales `[1.0, 0.2, 6.0, 0.1]` and pointers to `cross_low`, the referral discount, the keep share, the argument
block, `add_low` and the first cross rate. A stub takes that call: its inputs are compared with the model on every
vector, and its result is an input of the vector.

### Update

`0x3744550(out, state, patch)` clones the three `Vec`s and the map into a stack copy, applies nine optional parts,
and calls the ladder on that copy.

| Patch offset | Present when | Replaces |
|---|---|---|
| `+0x00`, value `+0x08` | low bit | four base rates |
| `+0x28`, value `+0x30` | non-zero | `+0x68` |
| `+0x38`, value `+0x40` | non-zero | `+0x70` |
| `+0x48`, value `+0x50` | low bit | map, the clone is dropped |
| `+0x68`, value `+0x70` | low bit | three words at `+0x90` |
| `+0x88`, values to `+0xb7` | not `i64::MIN` | vip and mm `Vec`s together, clones freed |
| `+0xb8`, values to `+0xcf` | not `i64::MIN` | stake `Vec`, clone freed |
| `+0xd0`, value `+0xd1` | low bit | 20 bytes at `+0xa8` |
| `+0xe5` | not 2 | byte at `+0xbc` |

On acceptance the old schedule is dropped and the copy moves in. On rejection the copy is dropped and the state
stays as it was. vip and mm can only be replaced together.

## Implementation and comparison

Implementation: not yet implemented. `tools/fees_schedule_admission.py` holds a closed-form model for test use
only.

Method: a table decoder (no external program) gives the instructions, and a Python evaluator runs them. Memory is
strict: reading a byte nobody set is a fault, so the vectors also show the ladder never reads the map keys, or
`+0xa8` and `+0xbc`. Stubs spoil caller-saved registers. The heap stub requires every block to be freed once with
its size, so both exits are shown to free everything. Patch memory of absent parts holds garbage.

| Measure | Value |
|---|---|
| ladder and floor vectors | 844, 0 mismatches |
| update vectors | 2061, 0 mismatches |
| instructions executed | 1612 of 1793 |
| conditional branches flipped | 184: 162 caught, 10 equivalent, 12 in code no vector reaches |

A vector matches only if acceptance, the exit instruction, each floor exit, the number of grid calls and all grid
inputs agree with the model. The update model must predict the merged copy, the tag, the final state, the blocks
left, and each clone and drop call.

The evaluator and the model agreed on the first complete run, apart from one mistaken allocation vector. Agreement
alone proves little, so the vectors were tested by flipping every conditional branch. That found a real gap: no old schedule had 2 or 4 mm rows, so a flip in the tail of the mm clone
loop survived, and shapes `e` and `f` now close it. The remaining survivors are listed with reasons in
`branch_survey.equivalent`, and the tool fails on any other survivor. One of them is a result: the fourth list of the last range check, flipped off entirely, changes
nothing, because it holds only values already tested in the second and third lists. Unexecuted instructions are
listed the same way in `unexecuted_ranges`: unwind cleanup, jumps after calls that do not return, and blocks the
list seeds make unreachable.

`reference-diff.tsv` compares with the reference tree. It has no admission rule. `l1/action/vote_global.rs` gives
`FeeSchedule` nine u64 bps fields, while the patch here has nine parts of quite different shapes, so the count
matches and the types do not. `info_server/abci_state_info_handler.rs` has the first four rate names right and
gives `FeeTier` five fields, while the ladder reads six words per vip row.

## Results and limitations

Inferences, not observations:

- `0x3744550` applies a `NewFeeSchedule` action: the binary has the text `struct NewFeeSchedule with 9 elements`
  and the patch has nine parts. Which action tag reaches the three callers was not traced.
- The four vip columns are cross, add, spot cross and spot add, because each is seeded by that base rate. The
  serializer proves the base names, not the row names.
- The u64 at vip `+0x20` is `ntlCutoff`: it rises strictly from 0.
- The floors keep a margin after referral, stake and keep shares at the lowest rates, in the worst case for a
  negative add rate. Why the multipliers are 0.2, 6.0 and 0.1 is unknown.

Unresolved or not covered:

- The vip word at `+0x28` falls from 1.0 and has no name here. The vip serializer found at `0x2a3c09e` reads five
  words from `+0x00`, in a different layout from the six-word row, so how the two relate is open.
- Offset `+0x70`, the map and the three words at `+0x90` have no name proved by bytes. `l1/spot_meta.rs:174` has
  three scale fields as u64; if they are those words, the type there is wrong.
- `0x3404030` is a stub, so the grid behind it is not evaluated here, and a vector accepted here is accepted only
  under the stubbed grid result.
- Checks `discount_high` and `discount_low` were never the failure: for finite input the stake loop and the 0.5
  cap decide first. Floors `net_six`, `keep_six`, `keep_fifth` and `keep_plain` were never the first failure in
  any vector, and a short search with very large rates found none; this is not a proof that they cannot be.
- Non-finite rates were not analysed. Vector values are illustrations, not Hyperliquid's real schedule.
- The stubs for map clone, map drop and schedule drop model only the calls the update makes. No differential run
  against a live node was made, there is no Rust implementation, and node #115 was not checked.

Next question: which function reads vip rows at trade time and picks a row by volume, and does it use the word at
`+0x28`?
