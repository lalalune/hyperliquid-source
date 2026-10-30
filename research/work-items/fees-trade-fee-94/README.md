# fees: the trade fee of one fill in node #94, perp and spot

- Component ID: `fees` (first task: maker/taker fee formulas and time-window rollover; this packet fixes the fee formula of a
  fill, the rollover stays open).
- Target release and full SHA-256: hl-node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` /
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only, nothing copied).
- Claim status: observation for bytes, decoded instructions, the evaluated outcomes and the copy map; inference where marked;
  unresolved items are listed at the end.
- Scope included: `0x37130b0` (perp), `0x3742460` (spot) and their helpers `0x3743df0`, `0x3743020`, `0x3742070` in full. Scope
  excluded: the hash `0x399c7a0` (a stub), the writers of the rate rows, tiers and window maps, the use of the output after the
  copy into the side block, the accumulation in `0x37153f0`, and node #115.

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 tools/fees_trade_fee.py --out research/work-items/fees-trade-fee-94
python3 -m unittest tests.test_fees_trade_fee
(cd research/work-items/fees-trade-fee-94 && sha256sum -c MANIFEST.sha256)
# optional, for a human reader only; no evidence file uses this
objdump -d -M intel --start-address=0x37130b0 --stop-address=0x3713dac artifacts/node/94/hl-node
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input SHA-256 first and
fails on any other file. It starts no external program, so no binutils version can change its output. Sections and FDEs come from
`tools/elf_index.py` and `tools/fde_extents.py`. It does not run the node or visor: decoded instructions are interpreted in
Python. A full run takes about 270 seconds and writes `evidence.json`, `vectors.tsv`, `mutations.tsv`, `instructions.tsv` and
`reference-diff.tsv`.

## Evidence

All addresses are ELF virtual addresses. Function ranges come from `.eh_frame`, and the decoder must land on each FDE end
(`evidence.json`, `functions`).

### Where the code is

| Function | FDE range | Instructions | Role here |
|---|---|---|---|
| `0x37130b0` | `0x37130b0..0x3713dac` | 723 | perp fee of one side of a fill |
| `0x3742460` | `0x3742460..0x374301c` | 662 | spot fee of one side of a fill |
| `0x3743df0` | `0x3743df0..0x374401f` | 128 | rate row of an address |
| `0x3743020` | `0x3743020..0x37433b3` | 218 | discount of an address |
| `0x3742070` | `0x3742070..0x3742453` | 231 | window sum, anchor and weight of an address |

`0x37130b0` has no direct call. Slot `0x5774890` names it through a RELATIVE relocation and seven `call [rip+d]` sites use it
(`evidence.json`, `perp_callers`). Six load the notional as the immediate `0x3b9aca00` (1e9), in the two-call pairs of
`0x26eff10`, `0x431c530` and `0x431d020`. In `0x431c530`, read by hand, the caller divides output `+0x50` by 1e9 and passes the quotient to the slot
`0x5774898` call. The seventh, `0x3710d45` in `0x3710a70`, passes a notional from a register, then copies the output into the side
block (below). `0x3742460` has five direct calls (`spot_callers`).

### Inputs

Perp: `0x37130b0(out, state, record, ntli)`. Spot: `0x3742460(out, ctx, record)`.

| Word | Perp record | Spot record |
|---|---|---|
| option bit, amount units, 20-byte address | `+0x00`, `+0x08`, `+0x10` | `+0x00`, `+0x08`, `+0x10` |
| `ctx` | `+0x28` | second argument |
| asset | `+0x30` | |
| weight f64, bucket byte, leg byte | | `+0x28`, `+0x30`, `+0x31` |
| notional | fourth argument | `+0x38` |
| 20-byte user | `+0x38` | `+0x40` |
| side byte `s` | `+0x4c` | `+0x54` |
| other bytes | `+0x4e` (`flag`) | `+0x55` (`al`), `+0x56` (`flag`) |

The perp admission is the same as in `0x37153f0`: `asset / 10000 == [state+0x30]` and `asset % 10000 < [state+0x10]`, or a panic at
`l1/src/perp_meta.rs:194:38`. The asset byte `+0x29` selects a scale from `.rodata` `0x204350`: `[1.0, 0.1]`. `x` is
`[[state+0x208]+0x60]`, or 0 when byte `[state+0x230]` is 3. Byte `[state+0x58]` is `trial`. A negative notional panics with
`Result::unwrap` at `l1/src/qtys/mod.rs:843:1` after the rate calls.

### Rate row, `0x3743df0`

Twenty `0xff` bytes or twenty `0xfe` bytes (`evidence.json`, `facts`) give an all-zero row. Otherwise the 20-byte key is hashed and
looked up in one table at `ctx+0xc0`, mask `+0xc8`, items `+0xd8`, 0xe8-byte buckets, SSE group probing. A missing key or a low tag
byte of 0 gives `ctx+0x48..+0x68` with key word 0.0 and flag 0. Otherwise the row comes from the bucket:

| Row word | Bucket end offset | Use here |
|---|---|---|
| `+0x00`, `+0x08` perp rates | `-0xc8`, `-0xc0` | `rate = row[s ? 0 : 1]` |
| `+0x10`, `+0x18` spot rates | `-0xb8`, `-0xb0` | the same in spot |
| `+0x20` anchor | `-0xa8` | tier key |
| `+0x28..+0x48` | `-0xa0` | copied, not read here |
| `+0x48`, `+0x50` perp second rates | `-0x80`, `-0x78` | read when the flag is not 0 |
| `+0x58`, `+0x60` spot second rates | `-0x70`, `-0x68` | read when the flag is not 0 |
| `+0x68` flag, 32 bits | `-0x60` | |
| `+0x70` weight | `-0x58` | |

### Discount, `0x3743020`, and window, `0x3742070`

The same bucket holds a B-tree map at end `-0x38` (root), `-0x30` (height), `-0x28` (length). Both helpers walk the first `length`
items in order and add the first word of each 0x30-byte value. An overflow calls the recorder at ``l1/src/qtys/impl_ntl.rs:664:1`` and saturates.
A null root gives sum 0 and the length is not read.

- `discount(a)`: 0.0 unless the bucket exists and byte end `-0x1c` equals 1. Then `ctx+0x68` if the sum is below 2,500,000,000
  (`sum >> 8 <= 0x9502f8`), else 0.0.
- `window(a)`: `(0, 0.0, 1.0)` without a bucket. Otherwise the sum, and `(row +0x20, row +0x70)` when the 32-bit tag equals 1, else
  `(0.0, 1.0)`. So a tag of 2 is a row for `0x3743df0` and no row for `0x3742070`, and a tag of 0x100 the reverse.

### Perp formula

`t(x)` is the repeated conversion: non-finite gives 0, otherwise truncate toward zero and saturate to `i64`.

```text
leg(rate):
  if rate < 0:  s = min(x / (x + 1), 0.5);  a = s * rate;  b = (1 - s) * rate
                m = trial ? (s_byte ? ctx[0x90] : ctx[0x98]) : 1
  else:         a = x * rate;  b = max(x, 1) * rate
                m = (trial and s_byte) ? ctx[0x90] : 1
  u = asset byte ? 1.0 : 0.1
  p = m * b * u;  a = a * u
  unless a < 0 or p < 0:  d = discount(user);  a *= 1 - d;  p *= 1 - d
  return a, p

(a1, p1) = leg(second rate)                 only when the row flag is not 0
(a2, p2) = leg(rate)
fee   = t((p2 + a2) * ntli)
extra = flag ? max(t(max(p1 + a1 - (p2 + a2), 0) * ntli), 0) : 0
gross = max(fee, 0) + extra
```

Builder, when bit 0 of the option word is set: `b = max(t(units / 100000 * ntli), 0)`, and `gross = b + gross`, recording at
``l1/src/qtys/mod.rs:829:1`` and saturating to `u64::MAX` on carry.

After that, only when `fee > 0`, one of two shares can apply. `step(k)` is the value of the last row of the 16-byte table
`ctx+0x38`, length `+0x40`, whose threshold is not above `k`, and `top = step(row(a).anchor)`.

1. Builder tier, when a builder is present and `flag` is 0. Skipped when the table is empty, when the first threshold is above the
   builder's anchor, or when `top` is 0. `(_, k, w) = window(user)`, `low` is `step(k)` or 0, and `g = max(t(fee * (w * max(top -
   low, 0))), 0)`. When `g > 0` the builder amount grows by `g`, `net = fee - g`, and step 2 does not run.
2. Referrer, when the items count is not 0, the bucket exists and bit 0 of byte end `-0x1c` is set. The address is at end `-0x1b`.
   `(sum, k, w) = window(user)`. The share `y` is 0 when `sum >= 1e11` (`sum >> 11 > 0x2e90edc`), `ctx+0x70` when `flag` is set,
   otherwise `max(w * (top - low), 0)` when the referrer has a tier and `top > 0`, else 0. `amount = max(t(fee * y), 0)`, `net = fee - amount`.

Last, with `net = fee` when neither applied: `share = a2 / (a2 + p2)`, or 0 when the sum is 0. `deployer = t(net * share)` and
`protocol = net - deployer`, saturating and recording at ``l1/src/qtys/impl_ntl.rs:62:1``. `rebate = -fee` when `fee <= 0`, else 0.

### Spot formula

The same with these changes, each decoded in `0x3742460`:

- Rate from row `+0x10/+0x18`, second rate from `+0x58/+0x60`. No asset scale and no `x`.
- Bucket byte `c` on the first rate: 0 keeps it, 2 gives `max(rate, 0) * weight`, any other value gives `rate / 5`. On the second
  rate: 0 keeps it, 1 gives `rate / 5`, any other value gives `max(rate, 0) * weight`. So values 3 and up differ between the two.
- Multiplier: `m1 = (al and s_byte) ? ctx[0x90] : 1`, and for a negative value `(al and not s_byte) ? ctx[0x98] : m1`.
- The discount applies when the value is above 0.
- Leg byte 0: the fee uses the second rate when the flag is set, and the first rate otherwise. Gross is `max(fee, 0)`, and there is
  no extra, builder or referrer: the function writes both option tags as 0.
- Leg byte 1: `extra = max(t(max(second - first, 0) * ntli), 0)` when the flag is set, then builder and shares as in perp.
- No deployer or remainder words. The output record ends at `+0x68`.

### Output

| Output | Word | Side block (perp fill) |
|---|---|---|
| `+0x00` | referrer tag, 0 or 1 | `+0x58` |
| `+0x08` | referrer amount | `+0x60` |
| `+0x10` | referrer address | `+0x68` |
| `+0x28` | builder tag | `+0x80` |
| `+0x30` | builder amount | `+0x88` |
| `+0x38` | builder address | `+0x90` |
| `+0x50` | gross, builder included | `+0xa8` |
| `+0x58` | rebate | `+0xb0` |
| `+0x60` | extra | `+0xb8` |
| `+0x68` | deployer | `+0xc0` |
| `+0x70` | protocol | `+0xc8` |

The last column is the copy at `0x3711118..0x371118d`, read from decoded operands (`evidence.json`, `fill_copy`). These side offsets
are the ones `0x37153f0` reads. A tag of 0 leaves the amount and address words unset. The strict evaluator allows that read at
eight listed copy instructions only.

### Examples

Both engines agree on these, with rates add 1e-4 and cross 3.5e-4 (perp), 2.5e-4 and 7e-4 (spot), notional 1e12
(`evidence.json`, `examples`):

| Case | gross | rebate | deployer | protocol | referrer | builder |
|---|---|---|---|---|---|---|
| taker, default row | 350000000 | 0 | 0 | 350000000 |  |  |
| maker, default row | 100000000 | 0 | 0 | 100000000 |  |  |
| asset byte clear | 35000000 | 0 | 0 | 35000000 |  |  |
| deployer scale 0.5 | 524999999 | 0 | 174999999 | 350000000 |  |  |
| deployer scale 2 | 1400000000 | 0 | 700000000 | 700000000 |  |  |
| negative rate, scale 1 | 0 | 20000000 | -10000000 | -10000000 |  |  |
| referred, flag side | 336000000 | 0 | 0 | 302400000 | 33600000 |  |
| builder 10 units | 450000000 | 0 | 0 | 350000000 |  | 100000000 |
| exempt address | 0 | 0 | 0 | 0 |  |  |
| spot, taker | 700000000 | 0 |  |  |  |  |
| spot, bucket 1 | 140000000 | 0 |  |  |  |  |
| spot, bucket 2 weight 0.25 | 175000000 | 0 |  |  |  |  |
| spot, no quote leg | 700000000 | 0 |  |  |  |  |

The 524999999 is float truncation: `1.5 * 3.5e-4 * 1e12` is just below 525000000 in binary64.

## Implementation and comparison

Implementation: not yet implemented. `tools/fees_trade_fee.py` holds a closed-form model for test use only. No Rust build, so no
two-build result and no normalization mask.

Method: a table decoder gives the instructions and a Python evaluator runs them. Memory is strict: reading a byte nobody set is a
fault, apart from the eight copy loads above. Stubs spoil caller-saved registers. The real hash table and B-tree shapes are built
in memory for each vector, so the probe loops and the tree walks run. The hash is a stub that reads the 20-byte key, so every lookup
is checked as a sequence of keys against the model. Callee-saved registers are checked on return.

| Measure | Value |
|---|---|
| vectors | 2840, 0 mismatches |
| exits | perp normal 1318, perp asset panic 48, perp negative notional panic 48, perp tree end panic 4, spot normal 1368, spot negative notional panic 48, spot tree end panic 6 |
| instructions executed | 1918 of 1962; the rest are the listed ranges and 10 padding `nop`s |
| mutants | 278: 250 killed, 28 equivalent, on 1116 sampled vectors |

The unexecuted ranges are listed with a reason in `evidence.json`, `unexecuted`, and the tool fails on any other. They are the builder
`+inf` arm in both copies (a finite `u64 / 100000` times a finite `i64` is finite), the referrer `net` overflow recorder in both
copies (`fee > 0` and `amount >= 0` cannot overflow), and two `None` unwraps with their `ud2` in the helpers (a null root never enters
the walk).

The first evaluator run on the perp vectors had 169 mismatches and the first full run 5. All were errors of the model or of the test
memory, not of the decoder: the helper skips the hash when the items count is 0, a null root ignores the length, and one vector
class built an invalid tree. Then the flips ran: each conditional jump, conditional move and `set`, plus five `.rodata` constants
and three immediates. Two sweeps found real gaps, and the directed groups `second_trial`, `second_rebate`, `second_bucket`, `carry` and a second `twin` close them. The 28 survivors are 22 clamps before a conversion (`cvttsd2si` and the next `cmova` already saturate), 2 flips inside the dead recorder, 1 share branch where `fee` and `net` are already 0, and 3 spot branches where both arms give the same value. Every survivor has its reason in `mutations.tsv`.

As a one-off authoring check, not part of the evidence, GNU objdump 2.42 listed the same addresses for all five functions.

`reference-diff.tsv` compares with the reference tree. In short: `l1/fees/compute.rs` reads these side fields and has no producer. The
layout of `FeeTrialRecord` in `55_start_fee_trial.rs` matches the row words, and the step scan matches `resolve_volume_discount`, but
that file puts the records in a `BTreeMap` and the bytes read one hash table that also holds the referrer binding. The third side
amount, which `compute.rs` calls `protocol_component`, is `extra` here. The deployer split, the 0.5 cap and the 1e11 and 2.5e9 limits
appear in no fee path of the reference.

## Results and limitations

Inferences, not observations:

- `s` means maker. `0x431c530` makes its first call with 0 and its second with 1, `0x3710a70` sets it with `sete` on a side compare,
  and the reference orders `FeeRates` as add then cross, which gives makers the add rate.
- `x` is the deployer fee scale of a builder-deployed perp dex, `a` the deployer part and `p` the protocol part. The names rest on
  byte `[state+0x230]`, on the 0.5 cap and on `deployer` being the share `a / (a + p)` of `net`. No text in the binary names them.
- Rows are fee trial records in the reference's sense, so `extra` would be what the old rates would have charged above the trial
  rates. `gross` includes it.
- The two limits read as volume caps: 2.5e9 stops the referred user's discount and 1e11 stops the referrer's share. The unit of the
  map values was not established, so no dollar figure is claimed.
- The six 1e9 calls are rate probes, not charges: the caller keeps only `gross / 1e9`.
- The fill keeps the order of the grid at `0x36e2d90`: discount inside the float product, then truncation, then the keep share from
  the truncated integer. So `D` and `K` there mirror `fee` and the referrer amount here. The grid's scale list `1, 0.2, 6, 0.1` holds
  the `/ 5` and `0.1` scales seen here. `6` is not seen here.

Unresolved:

- Who writes the rows, the tier table, `ctx+0x68`, `+0x70`, `+0x90`, `+0x98`, and what the map values are. Vector values for them are
  illustrative, not read from any state.
- Whether a spot bucket byte of 3 or more occurs. Callers pass 2 or a register.
- The use of output `+0x60`, `+0x68`, `+0x70` after the copy.
- NaN inputs were not run. Non-finite results of finite inputs were (the `extreme` group).
- Mutation kills are from a sampled vector set, and the hash stub stands in for `0x399c7a0`.

No progress gate is requested.

Next question: which function moves `deployer` and `protocol` from side `+0xc0` and `+0xc8` into balances, and what do the values of
the bucket's B-tree map count?
