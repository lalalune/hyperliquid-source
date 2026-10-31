# RE-004: amount rules of the node #94 user outcome actions (split, merge, merge question, negate)

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the decisions, the output fields, the call site and string census, and the status text; inference for which gate serves which action and for the role of the record fields; unresolved items are listed under limits
- Scope included and excluded: included are four gates `0x37250d0`, `0x3724f20`, `0x37253c0`, `0x3725ab0`, the helper `0x385c150`, and the leg builders `0x3726750`, `0x3726ed0`, run from entry as real bytes over real hash table and B-tree layouts. `0x3c18fb0`, `0x3c18150` and `0x3394620` run as real bytes too. Excluded are the handler copies that call these gates, the merge leg builders behind slots `0x5773880` and `0x5773870` (listed by other open work), the amount converter, and everything after the legs.

## Reproduce

```
python3 tools/outcome_user_amounts.py --out research/work-items/RE-004-outcome-user-amounts-94
python3 -m unittest tests.test_outcome_user_amounts
```

Run from the repository root with Python 3 and the standard library; no external program is used, and the output hashes are in `MANIFEST.sha256`. The tool reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output and it does not execute the binary. A run takes about 40 to 90 s, depending on load.

## Evidence

Coordinates are virtual addresses. Rows come from the tool's own decoder (`function-rows.tsv`). The six public functions have a GOT slot each, with 3 `call` sites through it and no direct call (`slots.tsv`, `call-sites.tsv`). Other slots holding the same address were not searched by the tool.

Strings. `strings.tsv` pins `UserOutcomeAction::SplitOutcome`, `MergeOutcome`, `MergeQuestion` with 2 fields each and `NegateOutcome` with 3.

Status text. The result bytes of these functions index the Display at `0x3815010` (table `0x59b088`, 10 arms, `status-text.tsv`), which sits behind the `Outcome error: ` text:

| Status | Text |
|---|---|
| 0 | Invalid question |
| 1 | Invalid amount |
| 2 | Insufficient quote token balance |
| 3 | Insufficient outcome balance |
| 4 | Outcome not in question |
| 5 | Cannot negate fallback outcome |
| 6 | Cannot split fallback outcome |
| 7 | Internal |
| 8 | Unexpected |
| 9 | Outcome already has supply |

Tables. In the state `S` passed in `rsi`:

- Outcome hash table at `S+0xd0` (mask `+0xd8`, items `+0xe8`, stride `0x90`). Record: `+0x00` id, `+0x28` side 0 token, `+0x50` side 1 token, `+0x88` unit.
- Question hash table at `S+0x100` (mask `+0x108`, items `+0x118`, stride `0x70`). Record: `+0x00` id, `+0x38` fallback outcome, `+0x40` B-tree set root, `+0x48` height, `+0x50` length.
- Quote token `q` of an outcome: `0x3c18fb0` maps each side token through token row `S+0x180` (stride `0xe8`, one spot only: `+0x60 == 1`, spot index at `[+0x58]`) to spot row `S+0x168` (stride `0x20`), `+8`. Both sides must agree.
- `avail(t)`: balance map of the user behind slot `0x5773170`, key `t`, value total `+0` and hold `+8`, `total - hold`. Absent is 0. Hold above total goes through the recorder with Location `l1/src/qtys/impl_wei.rs:6:1` and gives 0.

`convert(t, text)` below is slot `0x5774af8`, a stub here. It returns `v`, a u64 in token `t` wei, or an error.

Gate `0x37250d0` (result byte 0 ok, 1 error, status byte +1):

1. Slot `0x5774760` returns a record whose `+0x30` equals the outcome: status 6.
2. Outcome absent, a side refused, or sides on different quote tokens: status 8.
3. `v = convert(q, text)`. Error, or `v % unit != 0`: status 1. `v = 0` passes here.
4. `avail(q) < v`: status 2.
5. Ok: outcome, `q`, `v`.

Gate `0x3724f20` with helper `0x385c150` (word 0: 0 none, 1 some, 2 error with status byte at `+8`):

1. Outcome absent, a side refused, sides on different quote tokens, or unit 0: status 8. The helper's own status byte (4, 0, `0xf`) is never read.
2. `m = min(avail(side 0), avail(side 1))`, read before the amount.
3. No text: none. The output word beside it is undefined.
4. `v = convert(q, text)`. Error, or `v % unit != 0`: status 1.
5. `m < v / unit`: status 3.
6. Ok: `v`, not `v / unit`.

Gate `0x37253c0` (error: word 0 is `2^63`, status byte at `+8`):

1. Question absent or outcome table empty: status 8.
2. Members are the fallback, then the set in key order. A member with no record: status 8, vector freed. Vector rows hold `(outcome, side 0 token)`. `m` is the least `avail(side 0 token)`.
3. No text: amount `m`. With text: `v = convert(token of the fallback, text)`, error status 1, `m < v` status 3. No unit is read.
4. Ok: vector, fallback, amount.

Gate `0x3725ab0` (same error form):

1. Question absent: status 8. The outcome equal to the fallback: status 5. Not in the set: status 4. No record: status 8.
2. `b` is the outcome's side 1 token. `v = convert(b, text)`, error status 1. `avail(b) < v`: status 3. No unit is read.
3. Every other member, with the fallback first: a row `(member, its side 0 token)`. A member with no record: status 8, vector freed.
4. Ok: vector, outcome, `v`, `b`.

Leg builders:

- `0x3726750` from `(outcome, q, v)`: one debit row `(outcome, q, v)`, two credit rows `(outcome, side 0 token, v / unit)` and `(outcome, side 1 token, v / unit)`, division floored. Outcome absent writes byte 4 and word 4 at `+8`; `unit > v` writes word 3 at `+8`. No remainder test here; the gate's test comes first.
- `0x3726ed0` from `(rows, outcome, v, b)`: one debit row `(outcome, b, v)`, one credit row `(member, token, v)` per input row. `v = 0` writes word 3 at `+8`. The input vector is freed.

Divides: `divisions.tsv` lists all 6, one 64-bit and one 32-bit form in each of three functions, chosen by `(a | b) >> 32`. None has a zero test on `unit` in these rows. In `0x385c150` the unit word doubles as the failure marker, since 0 there means failure.

## Implementation and comparison

Rust implementation: not yet implemented.

Comparison with `references/can1357-hl` (a clue, not a source): a case-insensitive search of the tree for the four action names finds no counterpart of these rules. `l1/exchange/impl_execute_action.rs` only names `userOutcome` in a comment, and `SpotUserOutcome` in `l1/exchange/handlers/27_spot_user.rs` is an unrelated result struct. Its `impl_outcome.rs` covers settlement and generated orders. Its status numbers are not this table: it has 4, 15, 18, 20 and 0, while the merge gate here replaces all helper failures with 8. Nothing here confirms or refutes its settlement functions.

## Results and limitations

Results from `evidence.json`:

- 200 named cases and 400 generated cases run from entry, with 0 mismatches against a separately written specification. Whole output areas, stub arguments, event order, vector rows and leg blocks are compared. Named outcomes are in `outcomes.tsv`. The first draft of the specification returned `v / unit` from the merge gate; the bytes disagreed, and the rule above is the corrected one.
- `mutations.tsv`: 532 byte edits on reached rows of the seven functions, 498 killed, 34 survived, each with a recorded reason. An unexplained survivor stops the tool. An unedited image must also pass under the mutant step limit. Most survivors are the same-tag `pshufd` selector, tree heights the fixtures do not build, and status bytes nothing reads.
- Unreached rows are listed per function (`unreached_rows`): landing pads, the allocation failure paths, B-tree descents of height 2 or more, and the `0x37259da`/`0x37259e1` status 0 exits of the merge question gate. Those two need an empty member list, and the fallback always gives one row.

Limits:

- `0x399c4a0`, `0x3762510` and the slot calls are stubs. The hash is a fixture, so the fixtures show probing and layout, not real bucket placement.
- `convert` is a stub. Read by eye, `0x37601e0` gives `Send amount cannot be zero` (tag `0x15c`) unless the decimal is positive, then scales by token `+0x49`. That read is why `v = 0` looks unreachable, and it is not generated evidence.
- Only the bounds and rules above are claimed. The arithmetic is checked by vectors and edge cases, not by a whole-domain proof.
- A record with unit 0 faults in `0x37250d0` and `0x3726750`. Whether any writer can store 0 is not read. The failure-marker use suggests a non-zero type.
- The writers of `+0x88` are not read, so "unit" is a label from its use. It reads as quote wei per side token. Other names (`side`, `avail`, `m`) are labels of this packet.
- Slot `0x5774760` is a stub. Status 6 text is the only evidence that its record names a fallback outcome.
- Which gate serves which action comes from reading one handler copy by eye, not from generated evidence. In that reading the handler parses each amount a first time before the gate, which is outside this packet.
- Merge leg builders are not covered, so what merge does with `v` afterwards is not claimed.

Inferences, not generated evidence: the variant order, the field counts and the status text fit `0x37250d0` = split, `0x3724f20` = merge outcome, `0x37253c0` = merge question, `0x3725ab0` = negate. Status 6 and status 2 belong to split, status 5 to negate. In that reading split text is in quote token units and must make a whole number of side tokens. Merge outcome text is in quote units too, compared against side tokens. Merge question and negate text are in side token units, with no unit test.

The analysis ran to completion for the scope above. No progress gate is requested.

Next question: which writer fills record `+0x88`, and does a settled outcome or question change what these gates admit?
