# staking: ValidatorL1Vote and ValidatorL1Stream in node #94

This packet shows how validators vote L1 actions and post a rate in node #94, so a reconstruction can write the `validatorL1Vote` path from bytes: eight variant gates, a tracker row per action, a stake snapshot and a 7 day time fixed when the row opens, a limit of 49 voted rows per voter, a strict stake quorum of 2/3 or of 1/5 for the nested action, and an apply that runs once and is not retried after a refusal.

- Component ID: staking (Staking and validator lifecycle; RE-010 arms 21 and 22)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a lead only. Nothing is copied from it.
- Claim status: observation for everything under Evidence, from ELF bytes and an evaluator of those bytes. Variant labels marked inference in `variants.tsv` are inference. Unresolved items are under limits.
- Scope included and excluded: included are the whole functions `0x22cdb40`, `0x27067d0`, `0x3949140`, `0x325e1f0`, `0x2fe2d80`, `0x3946120`, `0x3941380`, `0x33edb10`, `0x33c0850`, `0x21e0370`, `0x2706e40`, `0x33a7e30`. `0x3bde1f0` runs as real bytes but is not mutated, because #919 owns it. Excluded, and stubs here: the apply body `0x2387390`, the active set `0x3c10fa0`, the stake snapshot `0x336d5b0`, token name check `0x3cb0170`, decimal parse and float conversion, leaf inserts, set inserts, clones and drops.

## Reproduce

From the repository root:

```
python3 tools/validator_l1_vote.py --out research/work-items/staking-validator-l1-vote-94
python3 -m unittest tests.test_validator_l1_vote
```

The tool takes about 3 minutes with 4 worker processes. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no objdump or readelf. The binary is never executed: an interpreter inside the tool evaluates its bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `callers.tsv`, `copies.tsv`, `constants.tsv`, `field-names.tsv`, `status-text.tsv`, `variants.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Virtual addresses. Function bounds are FDE bounds. Slots come from `.rela.dyn`. Rows quoted here are bound in `constants.tsv`, so a moved row fails the run.

### Path

```
arm 21  handler 0x22cdb40   variant gate, clone
  host 0x27067d0            clone, tracker, on a finish clone again and apply 0x2387390
    body 0x3949140          gates, row count, row lookup, new row
      0x325e1f0             has this voter voted in this row
      0x2fe2d80             action key order
      0x33c0850             row insert
      0x3946120             store the vote; 0x3941380 reads quorum before and after
        0x33edb10           stake test
        0x3bde1f0           listed ratio (#919)
arm 22  wrapper 0x21e0370   clone
  0x2706e40                 member, length, range
    0x33a7e30               row upsert
```

Other copies: `copies.tsv` lists `0x4cf1650`, `0x4cf1cc0`, `0x4cf2330`, `0x4cf2680`. Rows and sizes match. Two of them read the state at `+0xa80` higher offsets (`0x40f8` for the tracker), which is a second state layout. They are compared by shape only.

### State

The tracker is state `+0x3678`. Serializer `0x3948260` names its fields (`field-names.tsv`): `prune_bucket_guard` `+0`, `atT` `+0x10` (rows), `hvs` `+0x28` (address set), `hc` `+0x40` (two f64), `active` `+0x50`. The text `struct ValidatorL1VoteTracker with 5 elements` is in rodata. `hvs` is the set at state `+0x36a0` that #919 calls the list of arm 84.

A row key is the 0x80 byte action. A row value is 0x70 bytes:

| Offset | Field |
|---|---|
| `+0` | text `l1_vote_tracker` |
| `+0x18` | copy of `hc` at the row's birth |
| `+0x28` | one bucket: voters at `+0`, listed at `+0x18` of its inner row, finished byte at `+0x18` |
| `+0x40` | stake snapshot, length at `+0x50` |
| `+0x58` | f64 stake ratio |
| `+0x60` | 12 byte time, block time plus 604800 s |
| `+0x6c` | done byte, set at a finish, read by no row of this path |

### Variants

`word0` selects the variant: `word0 - 0x800000000000000a` when above `0x8000000000000009`, else 6. `variants.tsv` has all six jump tables.

| k | Shape | Gate in the handler | Ratio |
|---|---|---|---|
| 0 | String | len above 100 `0x143`, len 21 or more `0x140` | 2/3 |
| 1 | (bool, address) | none | 2/3 |
| 2 | (String, address) | `0x3cb0170`, its status returned | 2/3 |
| 3 | (String, bool) | as k 0 | 2/3 |
| 4 | (u64, bool) | none | 2/3 |
| 5 | (String, bool) | as k 0 | 2/3 |
| 6 | nested action | inner tag in {2,3,4,5,6,8,9}, else `0x140` | 1/5 |
| 7 | u64, 4 addresses | none | 2/3 |

k 3 is `DisablePerpDex` by the word at `0x1f4dabf`. The other labels in `variants.tsv` are inference from shape and apply calls. The inner tag is `word0 ^ 2^63`, and a word without the top bit counts as tag 3.

### Status order in the body

| Status | Text | Step |
|---|---|---|
| `0x94` | Invalid validator | 1: not `allow_all_validators` and caller not in `allowed_validators` |
| `0x94` | Invalid validator | 2: `active` is 0 |
| `0x36` | Too many pending votes | 3: caller is in the voters or listed set of 50 or more rows |
| `0x94` | Invalid validator | 4a: row exists, caller is not in its snapshot |
| `0x91` | Unknown validator | 4b: no row, caller has no `validator_to_profile` row |
| `0x94` | Invalid validator | 4b: no row, profile signer is not in the active set |
| `0x186` | | 5: vote stored or skipped; flag byte 1 only on a finish |

Step 3 counts every row, finished rows included. Row expiry is not read here, and no row of this path removes a tracker row (`past_expire_row_still_counts`, `cap_counts_finished_and_done`).

### A vote

One call passes the caller as both voter and listed address.

1. A voter goes in only if the caller is in the snapshot. A listed entry goes in only if the caller is in `hvs`. A caller in neither changes nothing and returns `0x186` with flag 0.
2. Quorum is read before and after a store. Only a false to true move finishes. A finished bucket stores and reports nothing more.
3. Quorum is `stake AND listed`. Stake: `float(voted) > float(total) * ratio`, strict, with voters outside the snapshot not counted and a `u64` sum overflow a panic. Listed: as in #919, from the row's own `hc`.
4. So 2 of 3 equal stakes is short, 200 of 300 is short and 201 passes. For k 6, 60 of 300 is short and 61 passes.

The row's snapshot, ratio and time never move once written (`row_hit_keeps_old_stakes`, `row_hit_keeps_expire`). A caller in `hvs` but outside the snapshot can open a row, and is then refused `0x94` on any row that exists (`hvs_only_can_open_but_not_join`).

### Apply

On a finish the host clones the action and calls `0x2387390`. Success gives flag 1. A refusal returns that status, and the row stays finished, so no later vote can apply it (`apply_fails_keeps_finished`). The handler writes tag 9 and the flag on success, tag 14 and the status bytes on failure.

### ValidatorL1Stream

In order: caller not in state `+0x908` gives `0x91`; text above 100 bytes `0x143`; parse status passes through; float failure `0xab`; NaN, infinity, any value with the sign bit other than -0.0, or above 1.0, `0x140`; else the row `(f64, block time)` is written to `risk_free_rate` at state `+0x3268`. 0.0, -0.0, 1.0 and subnormals pass. A refused rate keeps the old row. The text `struct ValidatorL1StreamTracker with 1 element` is in rodata.

### Reference compare

`l1/exchange/handlers/21_validator_l1_vote.rs` differs from the bytes here. `22_validator_l1_stream.rs` agrees on the order and bounds.

| Reference | Bytes |
|---|---|
| Status 148 needs validator mode and membership | allowed set or allow-all, then `active`; no mode test in this path |
| 145 when no validator set exists | 145 when a new row's caller has no profile |
| Limit counts the items the payload fans out to | Limit counts rows the caller already voted in |
| Prunes expired rows on each vote | No expiry read and no row removal in this path |
| Refreshes `expires_at` on each vote | Written once |
| Resets a row when the validator set id changes | No set id; the snapshot stays |
| Payload gates absent | Text limits, token check, inner tag mask |
| `quorum_reached` is a trait | Strict stake ratio AND listed ratio, 2/3 or 1/5 |
| A finalized vote may apply later | A refused apply is not retried |

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run`, written apart from the bytes, that predicts status, flag, stub events and full tree state after every operation.

## Results and limitations

- 177 named scenarios (count 9, stream 33, vote 135) and 300 generated scenarios: 0 mismatches.
- 1035 byte edits on reached rows of 12 functions: 920 killed, 115 survived (`mutations.tsv`). Each edit runs up to 30 named scenarios that reach its row, to bound the time. An unedited image must pass under the same step limit first. Survivor groups are reviewed classes, not proof of equivalence:
  - 13: copy into a stack guard that only an unwind reads
  - 12: move of the cloned sets into the return value: the body reads word 0 and drops the rest
  - 10: dangling pointer of an empty text: 0 instead of 1 copies nothing and is never read
  - 10: open: no named case tells this edit apart and it was not analysed further
  - 10: test on a map with a zero size key: it holds at most one row
  - 8: bound or pointer of the unrolled eight step tree descent: no tree here is that tall
  - 7: arm for an absent half of the voter pair: the only caller passes two present addresses
  - 7: copy of bytes past the status of a tracker refusal: the body writes only the status, so these bytes are stale stack
  - 5: compare length 21 instead of 20: the next byte is equal in every fixture key
  - 4: guard for a second finish in one call, which the finished byte rules out
  - 4: old rate returned to the stream body, which drops it unread
  - 4: scale of an index that is always 0 in a fresh node
  - 3: length of a fresh node, which is 0
  - 3: parent word of a fresh root: this path never climbs from it
  - 2: None test of the Option key: the niche word 0x8000000000000012 is never an action
  - 2: iterator built only for the drop stub, which frees nothing here
  - 2: one more byte in a node allocation
  - 1: both arms read the same sum for a non null stake map
  - 1: flag written on a path where the next row rewrites it
  - 1: fourth return word of the row insert, unread by the body
  - 1: inner tags 2 and 3 both pass the mask, so a niche word mapped to 2 instead of 3 passes the same way
  - 1: length read at the first row of a descended leaf: index 0 is below any length
  - 1: low byte of the tail word of the name; the head word store rewrites that byte
  - 1: one more byte in a copy of the vacant entry; that byte is not read
  - 1: pointer word for a free on a path that does not free; the refusal bytes past the status are stale stack
  - 1: sixth argument of the leaf insert stub, a zero size allocator reference
- Reached rows: 436 of 3233 rows are not reached (`evidence.json`). They are panic tails, allocation failures, landing pads and rows for trees deeper than three levels.

Limits:

- `0x2387390` is a stub, so the apply statuses are fed in. `variants.tsv` gives one call per arm.
- `0x336d5b0` and `0x3c10fa0` are stubs, so stake values and the active set are fixture inputs.
- Leaf inserts are stubs; splits are not run. The nested action's own compare `0x2fe28e0` and clones are stubs.
- Who removes tracker rows, who reads `prune_bucket_guard`, the done byte and the time at `+0x60`, and who writes `active`, `hvs` and `hc` are unresolved. So is the reader of `risk_free_rate` beyond serialization.
- Live values are not in the binary. Inner tag names are not resolved.

No gate is requested.

Next question: which function removes rows from `atT`, using `prune_bucket_guard` and the time at value `+0x60`?
