# RE-004: governance vote weight, stake lock multiplier and proposal quorum in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the row order, the weight rule and the value of every run; inference for what the words mean (lock, delegation lockup, quorum base); unresolved items are listed under limits
- Scope included and excluded: included are four functions run as real bytes: vote `0x398d1a0`, lockup raise `0x3c0f350`, propose `0x398d540`, drain of ended proposals `0x398cc10`. Stubs here: the delegated total behind slot `0x5774900`, the time add behind slot `0x576efb8`, the vote upsert `0x33a5470`, the map insert `0x339c6e0`, the map remove `0x33ac460`, the record drop `0x33f32f0`, the vector grow behind slot `0x5775700`, the free behind slot `0x576e010`. Excluded: the action wrappers around these functions, who sums delegations, and how the base word of the quorum is built.

## Reproduce

```
python3 tools/gov_vote_weight.py --out research/work-items/RE-004-gov-vote-weight-94
python3 -m unittest tests.test_gov_vote_weight
```

Run from the repository root with Python 3 and the standard library; no external program is used, and the output hashes are in `MANIFEST.sha256`. The tool reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output and it does not execute the binary. A run takes one to two minutes.

## Evidence

Coordinates are virtual addresses. Rows come from the tool's own decoder (`function-rows.tsv`). FDE extents are exact.

| Function | Extent | Rows | Reached by |
|---|---|---|---|
| vote | `0x398d1a0..0x398d53e` | 237 | slot `0x57732d0`, 3 indirect sites |
| lockup raise | `0x3c0f350..0x3c0f6d2` | 207 | one direct call, `0x398d3c9` |
| propose | `0x398d540..0x398dc84` | 400 | slot `0x5773338`, 3 indirect sites |
| drain | `0x398cc10..0x398d1a0` | 297 | slot `0x5774920`, 3 indirect sites |

Sites are in `slots.tsv`.

### State

`S` is the staking state. Serde keys pair each offset with a name from bytes (`field-names.tsv`): `S+0x198` is `proposals`, a map from a 32-byte key to a record of `0x78` bytes.

| Record offset | Key | Width |
|---|---|---|
| `+0x00` | `title` | string |
| `+0x18` | `description` | string |
| `+0x30` | `votes` | map, key 20 bytes, value `(u64 weight, u8 choice)` |
| `+0x48` | `quorum` | u64 |
| `+0x50` | `end` | time of 12 bytes (`i32`, `u32`, `u32`) |
| `+0x5c` | `proposer` | 20 bytes |
| `+0x70` | not named here | the long proposal byte |

The serde text says `struct Proposal with 7 elements`. `S+0x168` is `delegations`, `S+0x1f8` is `user_states`: a user row with a time at `+8`. Tag `0x12c`, whose text is "Action not allowed while staking long term", belongs to another reader of that time, which is the basis for calling it a lock (`status-text.tsv`).

### Vote

Arguments: `rdi` output, `rsi` `S`, `rdx` user, `rcx` proposal key, `r8` choice, `r9` now.

1. Map empty or key missing: `0x105`.
2. `now > end`: `0x108`. The compare is lexical, the first word signed, the other two unsigned. `now == end` passes.
3. User already in `votes`: `0x106`.
4. `s` = delegated total. `s == 0`: `0x107`. Nothing is written up to here.
5. Lockup raise on every delegation row of the user (below).
6. Weight. No user row: `s`. Else, with `L` the time at row `+8`:
   - date word of `L` is 0: `s`, and the word stays 0
   - `now < L`: `4*s` when `s < 2^62`, else `s`. The row stays
   - `now >= L`: `s`, and the date word of `L` is set to 0 in place
7. Upsert `(user, weight, low byte of choice)` into the record's `votes`. Status `0x186`.

`stake-pieces.tsv` runs both ends of each stake piece. Each piece has one path, compared row by row, and the operands enter only the `shr 0x3e` test and the `shl 2`, so the two ends stand for the whole piece. The rule holds for all u64 `s`.

### Lockup raise

`0x3c0f350` takes the delegations map, the user and the record's `end`. It finds the user's inner map and walks every row in order. Each row keeps the larger of its time at `+8` and `end`, with the same lexical compare. A missing user, a null inner root or a zero length returns with no write. It has no status. The text of tag `0xff` is "Cannot undelegate during lockup period after delegating or voting.", which fits this word. The reader of that word is not traced here.

### Propose

Arguments: `rdi` output, `rsi` `S`, `rdx` a record of `0x7a` bytes: strings at `+0`, `+0x18`, key at `+0x30`, base word at `+0x50`, now at `+0x58`, proposer at `+0x64`, mode at `+0x78`, long byte at `+0x79`.

1. Title length outside `1..=50`: `0x100`. Description length outside `1..=1000`: `0x101`.
2. Delegated total below `1000000000`: `0x102`. The bound is inclusive.
3. Key in the map: `0x103`.
4. Count of records whose 20-byte proposer matches, over the whole map. More than 2: `0x104`, text "Too many active proposals. Limit is {} per user." with the word 3 at `0x20ade8`. So the third row is admitted.
5. Seconds from the f64 values in `constants.tsv`: low byte of the mode 1 or 2 gives 120 short, 300 long; the other 254 bytes give 86400 short, 518400 long (`seconds.tsv`). The time add runs on `+0x58`.
6. `quorum = trunc(f64(base) * rate)`, rate `0.05` short and `0.1` long from `0x20bb20`, indexed by the long byte. The saturation rows above `2^64` exist in the bytes; the rates keep the product below `2^61`, so they are not reached.
7. Insert. Status `0x186`. Refusals free both strings.

The quorum rests on `base` and not on the proposer's stake (`test_quorum_is_not_a_function_of_the_proposer`).

### Value of the quorum

The stored word equals `base // 20` (short) or `base // 10` (long) for small values. It is not that integer floor for all `base`. Both rates are slightly above the fraction. For a base just under a multiple, the product can come within half an ulp of the next integer and round up. `first_above` finds the first such base from exact fractions:

| Long | First base | Stored | Floor |
|---|---|---|---|
| 0 | 6755399441055759 | 337769972052788 | 337769972052787 |
| 1 | 6755399441055749 | 675539944105575 | 675539944105574 |

Above `2^53` the u64 to f64 step also rounds. At the top of the domain the stored word is 52 (short) or 103 (long) above the floor. All rows are in `quorum-witnesses.tsv`, run through the real bytes. `10^17` gives exactly the floor in both.

### Drain

`0x398cc10` takes the map and `now`. It walks the map in key order and keeps each key with `now >= end`, so an end equal to `now` goes. It stores those keys in a vector, then removes each key and inserts its record into a new map, returned at the output. So at `now == end` a vote passes if it runs first, and the proposal is gone if the drain runs first.

### Reference compare

`l1/exchange/handlers/49_gov_propose.rs` and `50_gov_vote.rs` hold most of these names, and the status numbers and the four durations agree. Differences found in the bytes:

- `50_gov_vote.rs` says a second per-user table "may rewrite the effective stake" and hides it behind a trait. The rewrite is the rule in step 6.
- The reference tests only upper length bounds. The bytes and the tag text refuse a length of 0 as well.
- The reference falls back to a prepared weight when the proposer has no row, and keys the proposer with an extra `u32`. The bytes read only the delegated total, and the proposer compare covers 20 bytes.
- The reference computes the quorum from an `effective_weight` and calls that field a proposer snapshot. The base word at `+0x50` comes from the helper behind slot `0x5773330` in the wrapper, and it is not the stake tested at `0x102`.
- The reference has `checked_add` with status 190 for the end time. `0x398d540` has no such branch; any failure would be inside the time add, which is a stub here.

## Implementation and comparison

Not yet implemented. The tool's rule list (`spec_vote`, `spec_propose`, `spec_drain`) is a test oracle, written apart from the bytes under test, and it predicts each run: the output, all fixture bytes and the stub events.

## Results and limitations

- 170 named and 400 generated cases give 0 mismatches. Fixtures are real B-tree nodes of leaf, two-level and three-level shape, with stale keys in unused slots.
- 359 byte edits on the four functions: 346 killed, 13 survived, each with a reason in `mutations.tsv`. Six survivors are the eight-step descent bound, and the rows behind it are not reached (no tree here has height 8). Three are the first leaf length word, where only zero against nonzero matters. Two are the cast rows above the reachable product. Two are the dangling pointer of an empty vector. An unedited image must pass under the same step limit.
- `evidence.json` lists every unreached row: these descents, the panics, and the saturation move. Some of them are shown by inspection only.
- `first_above` is an exact argument for bases below `2^53`. The tool also checks 46000 bases through the model, 20000 of them right below each first base. Only the rows in the table and a few smaller bases run through the real bytes.
- The long byte is 0 or 1 in every case. A larger byte would index past the rate table, and no wrapper row was read to rule that out.
- Stubs pin inputs only. The delegated total, the time add, and the map writes are not claimed.
- Read by eye, not run: the closure at the three drain sites (`0x26ff1c1` and two copies) frees title, description and `votes` of each drained record and reads neither `quorum` nor a vote. So no tally was found in this binary, and this packet does not say where the result of a proposal is computed.
- The meaning of the choice byte is open. Serde text near this code lists `yes`, `no`, `abstain` with an enum name beside them, which suggests it; not traced.
- The base word is read by eye only: output word `+0x30` of the helper, a difference of two supply-like words with one more optional deduction. No claim is made about what it counts.

Next question: which function reads a proposal's `votes` and `quorum`, given that the drain closure drops both?
