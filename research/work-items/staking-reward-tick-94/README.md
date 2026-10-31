# staking: c_staking block tick, reward rate and payout in node #94

This packet shows how node #94 creates and pays staking rewards each block, so a reconstruction can write the path from bytes: three time buckets in one tick host, a rate of `(q - q*q/2) / (31557600 / seconds)` with `q = 0.015 / max(sqrt(T/b), 0.015)`, rewards debited from `native_token_reserve` into `validator_to_staged_rewards`, then commission, a pro rata delegator split, a 1.5x bonus while a user lock runs, and all leftovers back in the reserve.

- Component ID: staking (Staking and validator lifecycle)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference has no code for this tick, so nothing here comes from it.
- Claim status: observation for everything under Evidence, from ELF bytes and an evaluator of those bytes. Names not found in rodata are marked inference. Unresolved items are under limitations.
- Scope included and excluded: included are the whole functions `0x3996730`, `0x3373420`, `0x3c10d70`, `0x3be5630`, `0x33709f0`, `0x336f9f0`, `0x3c12170`, `0x37d9a10`, `0x37d9af0`, `0x37d9cf0`, `0x37d5e10`, `0x33bc0a0`, `0x33bc5f0`. `0x37d5e10` is only a helper row in #938, and `0x33709f0` and `0x3be5630` appear only as site rows in the recorder lists of #46 and #234. No open PR states their logic. Excluded, and stubs here: the sink `0x3990130` and the delegate core `0x398dc90` behind it (#46), the validator power map `0x3c10fa0`, the range search `0x2fe1490`, clones, leaf inserts, bulk build, sort, drops, and the metric blocks at the end of `0x3373420`, `0x33709f0` and `0x336f9f0`.

## Reproduce

From the repository root:

```
python3 tools/staking_reward_tick.py --out research/work-items/staking-reward-tick-94
python3 -m unittest tests.test_staking_reward_tick
```

The tool takes about 2 minutes with 4 worker processes. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no objdump or readelf. The binary is never executed: an interpreter inside the tool evaluates its bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `callers.tsv`, `constants.tsv`, `field-names.tsv`, `rate-table.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Virtual addresses. Function bounds are FDE bounds. Slots come from `.rela.dyn`. `S` is the staking state at Exchange `+0x8f8`. Field names come from the state serializer `0x238d300` and are bound in `field-names.tsv`.

### Path

```
slot 0x5773a30, sites 0x220a5ee 0x446e882 0x446f202
tick host 0x3996730(out, S, chain byte, exchange, tag, value)
  time to ms: days*86400 + seconds, *1000 + nanos/1e6, below 0 becomes 0
  bucket S+0x100/+0x108  fired when ms/width > last, last = max
    0x3373420 stage "c_staking_stage_reward"
      0x37d5e10 latest history row, 0x3c10d70 sum of word 1
      0x3c10fa0 power map (stub), 0x3be5630 one row per validator
  bucket S+0x110/+0x118
    0x33709f0 distribute "c_staking_distribute_staged_rewards"
      0x37d9cf0 latest history key, then one payout per staged row
      0x3990130 sink (stub), which calls 0x398dc90 per merged row
  0x37d9af0 jailed set history (S+0xb0)
  stake history gate, then 0x37d9a10 (S+0)
  bucket S+0xa0/+0xa8
    0x336f9f0 "decay_staking", 0x3c12170 one pass over live stakes
```

The two tag and value arguments come from a lookup at each call site: Exchange `+0x80` is an Option, `+0x88` its key, and the map at `+0x408` holds the value. Inference: this is the native token and its supply, because the formula divides staked weight by it.

### State layout, S relative

| Offset | Meaning | Source |
|---|---|---|
| +0x00 | two head words, copied into each history row | `0x37d9a10` |
| +0x10 root, +0x18 height, +0x20 len | `stakes`: address to (word 0, word 1), row 0x10 | `0x3c12170`, serializer key |
| +0x28 | stake history interval | host `0x3996b52` |
| +0x30 | low word of the window | `0x37d5e24` |
| +0x38, +0x48 | history map key to 0x28 byte row, len | `0x37d9a10` |
| +0x50 | history cap | `0x37d9a93` |
| +0x58 | current key | `0x3373472` |
| +0x60 tag, +0x68 value | `native_token_reserve`, Option | serializer `0x238d5ca` |
| +0xa0, +0xa8 | `stakes_decay_bucket_guard` width, last | serializer, host |
| +0xb0 | `jailed_signers` block: interval +0, history +0x10, set +0x28, cap +0x40 | `0x37d9af0` |
| +0x100, +0x108 | `stage_reward_bucket_guard` width, last | serializer, host |
| +0x110, +0x118 | `distribute_reward_bucket_guard` width, last | serializer, host |
| +0x150 | `validator_to_profile`: word +0x38 commission, +0x40 signer | `0x33709f0`, `0x3be5630` |
| +0x180 | validator to delegator tree, name not found | `0x3370fb7` |
| +0x1e0 | `validator_to_staged_rewards`: address to u64 | serializer, `0x3370aa7` |
| +0x1f8 | `user_states`: u64 balance, then lock time | serializer, `0x3370fb7` |

### Reward rate, `0x33734b2` to `0x337356a`

```
a == 0, or b == 0, or sum of word 1 overflows u64:  rate = 0.0
seconds = width_ms / 1000.0        must be > 0, else panic "assertion failed: other.0 > 0."
q = 0.015 / max(sqrt(T / b), 0.015)    T = sum of word 1 in the latest history row
h = 31557600.0 / seconds
rate = (q*q*-0.5 + q) / h
```

`rate-table.tsv` gives values. At T/b = 0.4 and a 1 hour bucket the rate per bucket is about 2.7e-6, and rate times buckets in a Julian year is about 0.0234. `q - q*q/2` is the start of the series for `1 - exp(-q)`. That reading is inference. The bytes stop at the second term. The floor makes `q` at most 1, so `rate` is at most `0.5 * seconds / 31557600`.

`0x3be5630` turns the rate into rows, in address order over the history row:

1. No profile for the validator: row is None.
2. Signer not in the power map: None. Signer in `jailed_signers`: None. Both tests use the signer, not the validator.
3. Rate below 0 or above 1.01: amount 0. Otherwise amount = floor(rate * word 0), saturating.
4. Amount 0: row is Some(0), no state change.
5. Reserve tag not 1: row is Some(amount), nothing is staged.
6. Otherwise reserve drops by min(amount, reserve), and `validator_to_staged_rewards[validator]` rises by that min, saturating. The row still says the full amount. A short reserve fires the recorder `0x358dcd0`.

The stake that earns is word 0. The weight in the rate is word 1, summed over all rows, whether they earn or not. All reads are from the history row, not live `stakes`.

### Payout, `0x33709f0`

Latest key missing (empty history or stale window): the staged map is taken and dropped, and the reserve does not get it back, so the result is None. Reserve byte 0: nothing moves and the result is None. Otherwise, for each staged (validator, amount) in address order:

```
no profile: kept += amount, next
f = commission word as f64 * 0.0001
commission = f <= 1.01 ? floor(f * amount) : 0
share = amount - commission, 0 with recorder when commission is above amount
user_states[validator].balance += amount - share     creates the row even if 0
commission != 0: row (commission, validator, validator, kind 0)
no delegator tree, or member weights overflow u64, or sum 0: kept += share, next
for each member, in address order:
  weight = member word +0x10 if member word +0x18 == latest key else word +8
  reward = floor(weight/total * share as f64)
  paid = min(reward, left); left -= paid; balance += paid (saturating, recorder)
  lock in user row is set and now < lock:
    half = reward >> 1, taken = min(half, reserve), reserve -= taken, balance += taken
    row amount = reward + half
  otherwise: lock word = 0, row amount = reward
  row amount != 0: row (amount, member, validator, kind 1)
kept += left
```

At the end the reserve gets `kept`. Tag not 1: tag becomes 1 and value becomes `kept`. Overflow: status `0xbe` goes to `0x3379490` and the value stays. The rows go to `0x3990130`, which adds each row into a map keyed by (address, kind) and calls `0x398dc90` once per row. Inference: rewards are moved from the user row into a delegation there, which is the next question.

The bonus row states `reward + half` even when the reserve pays less. A lock that has ended is cleared by the first payout that reads it. The compare is on signed date, then seconds, then nanos, and `now == lock` counts as ended.

### History and decay

History row, stake and jail alike: last key + interval, saturating, `<=` key of this tick means store a clone at this key, then drop the oldest rows while len > cap. The key is word `+0x30` of the exchange argument, a counter, not time. A row at the same key is replaced.

Latest row, `0x37d5e10` and `0x37d9cf0`: with `low` and `cur`, start = `low` while `cur < low + 2000` (saturating), else `max(cur - 200, low)`. The result is the last row with key at or past start, else None.

Decay, one pass over live `stakes` when its bucket fires:

```
word 1 >= word 0:  word 0 += trunc(0.99 * (word 1 - word 0) as f64)
word 1 <  word 0:  word 0 = word 1
```

So word 0 follows word 1. A rise closes 99% of the gap per bucket, a fall lands at once. A gap of 1 stays. In one tick the order is stage, distribute, jail history, stake history, decay, so a stored row holds values from before that tick's decay.

### Callers

`callers.tsv` lists every site. The host has one slot and three sites.

## Implementation and comparison

Not yet implemented in Rust. `tools/staking_reward_tick.py` evaluates the real bytes of the 13 functions under stubs over real B-tree nodes, and a rule list written apart from the evaluator predicts each run: outputs, recorder calls, statuses, drop counts, every map, and a digest of all other state bytes.

Cases: 209 named and 300 seeded vectors. All match. Every reached conditional row, immediate and field offset was edited one at a time, and each edit runs against every named case that reaches it: 961 edits, 839 killed, 122 survived.

Survivors by reason:

  - 21: iterator, vector and fresh node words read only by a stub, or rewritten before any read
  - 18: unrolled tree descent: both arms walk the same way on trees this low
  - 15: year at or below 0: time is negative, so the clamp to 0 hides the value
  - 13: entry copied to stack fields only the stubbed leaf insert would read, or a fresh node size, parent or bound
  - 12: finite and clamp tests: the cast saturates the same way, and no amount here is negative or infinite
  - 6: divide by 100 magic and its sign word: same quotient at every year used here
  - 6: wrong key count in a node scan: extra slots hold zero keys, so the search ends on the same row
  - 5: edge pointer of a walk deeper than two levels: no fixture tree is that tall
  - 5: lookup of a row this call just wrote: it never misses
  - 5: short or long sort, and a free on the empty path: stubs that behave the same
  - 4: sign mask of the cast at or above 2^63: doubles that large are even, so the lost low bit is 0
  - 3: choice of the 32 bit or 64 bit divide: both give the same quotient
  - 3: label length read only by the metric block the tool hops over
  - 3: length read at the first row of a descended leaf: index 0 is below any length
  - 2: add of the window to a low word past 2^64-2000: it always carries, so the sum is unused
  - 1: open: no named case tells this edit apart and it was not analysed further

Unreached rows: 1128 of 3755 rows, listed in `evidence.json`. Most are the metric blocks, which the tool hops over (`metric_hops` in `evidence.json`), plus unwind paths, panics and the eight step tree descent.

Tests: `tests/test_staking_reward_tick.py`, 69 tests pass, 0 skipped. They bind function bounds, slots, field names, constants and worked amounts, and they check patched bytes, a wrong digest, a wrong constant and a wrong field offset.

## Results and limitations

- Requesting no progress gate. This is one path of the staking component.
- `b` and the Option at Exchange `+0x80` are named by inference only.
- `0x3990130` and `0x398dc90` are stubs, so what the rows do to delegations is not shown here.
- The tick host returns the stage rows too. The caller walks them after the call, at `0x220a6d5`. That loop is not read here.
- The tree at S+0x180 has no serializer key in `0x238d300`, so its name is unknown. Who writes member words +8, +0x10 and +0x18 is unknown.
- Who moves `low` and `cur` is unknown. Tests here set them directly.
- `0x2fe1490` is a stub that returns rows at or past start. That is read from how the callers use its result, not from its body.
- Floats follow IEEE double in Python. `sqrt` matches `sqrtsd` for all values used.
- One survivor is open, `0x3be5ad5`, the height count of a power map search.

Next question: what does `0x3990130` hand to `0x398dc90` for kind 0 and kind 1 rows, and do those rows raise word 1 of `stakes`? That would close the loop from reward to stake.
