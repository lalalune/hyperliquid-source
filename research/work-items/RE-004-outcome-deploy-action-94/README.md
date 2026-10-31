# RE-004: OutcomeDeploy from dispatch to settlement gates: ten arms, count and length limits, settleFraction rules

This packet gives a Rust rebuild the admission rules of the `OutcomeDeploy` action, which the reference has no enum or handler for: ten arms behind one prelude (system user only outside chain byte 0, sticky status 7), a daily count of 500 or 50 by chain byte, lifetime caps of 9999 questions and 20000 outcome ids, name, text and list lengths, and the settlement rule that a question outcome takes exactly 0 or 1, a 1 needs a single named outcome left, and that winner settles the fallback to 0 in the same action.

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference holds lifted settlement helpers in `l1/exchange/impl_outcome.rs` and `l1/spot_clearinghouse/impl_outcome.rs`, compared below. It has no `OutcomeDeploy` type.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included are 16 whole functions. Handlers `0x2749880`, `0x4d66400`, `0x4d67e10`; settle wrappers `0x274b290`, `0x4d69820`, `0x4d69ae0`; fraction gate `0x3729df0`; name lengths `0x3c00f50`; text changes `0x3729ca0`, `0x3729830`; question record `0x3729990`; side circulation `0x3719210`; question insert `0x3728c20`; default sides `0x398cb60`; duplicate scans `0x372a910`, `0x372aea0`. Stubs with checked arguments stand for every callee outside this list. Excluded: the payout body behind the settle call, the `SettleQuestion` body, token registration and market deployment. Those functions already have rows in other packets, so they stay stubs and are named here by call site only.

## Reproduce

From the repository root:

```
python3 tools/outcome_deploy_action.py --out research/work-items/RE-004-outcome-deploy-action-94
python3 -m unittest tests.test_outcome_deploy_action
```

The tool takes one to three minutes on a loaded server. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `texts.tsv`, `arms.tsv`, `strings.tsv`, `locations.tsv`, `holders.tsv`, `copy-rows.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs. `S` is the state the handler receives. `T = S + 0x90` is the outcome tracker (`struct OutcomeTracker with 13 elements` is in rodata; the two-letter keys are not assigned to fields here).

### Prelude and dispatch

Handler arguments: result, `S`, user (20 bytes), action. Copy `0x4d66400` reads the chain byte at `S + 0x1372`, the other two at `S + 0x8f2`. `copy-rows.tsv` compares the copies row by row from bytes: 1306 and 1307 rows are identical or differ only in a call target or a rip displacement, and the single other row is that chain offset.

```
if user != 0 and chain != 0: refuse tag 0x8e   "Action disabled on this chain."
if S + 0x1e8 != 0:           refuse tag 0x17d status 7 "Internal"
word = action[0]; arm = word ^ 2^63 if word < 0 as i64 else 3
```

Arm 3 is the variant that carries a string in the first word, so its capacity is the niche. Results: byte 0 of the result is `0xd` for done, `0xe` for a refusal with the tag at `+8`, and `7` with the new word at `+8` for `RegisterOutcomeToken`.

| Arm | Variant | Fields read | Rules, in order |
|---|---|---|---|
| 0 | `RegisterOutcomeToken` | `+8` amount | `x >= 0x0ccccccccccccccc` tag `0x13f` with `x`; else token call with flag 1 |
| 1 | `RegisterOutcome` | `+8` name and text, `+0x38` sides, `+0x78` quote | daily +1, name lengths, duplicate standalone, `quote >= S+0x218` tag `0xea` with quote, market call |
| 2 | `RegisterTokensAndStandaloneOutcome` | `+8` name and text, `+0x38` sides, `+0x68` word | daily +1, name lengths, duplicate standalone, deploy call. No bound on the word here |
| 3 | `RegisterTokensAndQuestion` | `+0` and `+0x18` question strings, `+0x30` fallback name, `+0x68` list, `+0x70` n, `+0x78` quote | see below |
| 4 | `SettleOutcome` | `+8` fraction text, `+0x20` details, `+0x38` outcome | outcome known else `0xec`; fraction text `<= 100` else `0x143`; parse; details `<= 2000` else `0x143`; settle wrapper |
| 5 | `SettleQuestion` | `+8` question, `+0x10`, `+0x18`, `+0x20` tree root, height, length | question known else `0xed`; length `<= 50` else `0x143`; collect; settle body |
| 6 | `ChangeOutcomeDescription` | `+8` text, `+0x20` outcome | outcome known else `0xec`; text step |
| 7 | `RegisterQuestion` | `+8` name and text, `+0x38` fallback | outcome known else `0xec`; name lengths; question step |
| 8 | `RegisterNamedOutcome` | `+8` question, `+0x10` outcome | question known else `0xed`; outcome resolve; named outcome step |
| 9 | `ChangeQuestionDescription` | `+8` text, `+0x20` question | question known else `0xed`; text step |

The fraction is text in the action. Parsing happens in slot `0x5773328`, so the wrapper below gets an `f64`.

### Count limits

`S+0x1d8` is read as outcomes deployed today, `S+0x1c0` as the next outcome id and `S+0x1c8` as the next question id. Who writes the first two is not in this packet.

```
daily(k): if chain >= 2: limit = 500 if chain == 2 else 50
          refuse text "too many outcomes deployed today" if sat(S+0x1d8 + k) > limit
```

`chain` 0 and 1 have no daily limit. Arms 1 and 2 use `k = 1`. Arm 3 runs, in this order, before any string is cloned:

```
S+0x1c8 > 9999                 tag 0x17b "limit exceeded"
sat(S+0x1c0 + n + 1) > 20000   tag 0x17b "limit exceeded"
n > 50                         tag 0x143
daily(n + 1)
```

So a question deploys its named outcomes plus one fallback, and a batch of 49 named outcomes is the largest that fits the 50 limit from zero. Then: name lengths on the question, duplicate question, name lengths on the fallback, name list, default sides, deploy, one outcome per name, question step, named outcome step per id. A later failure refuses without undoing earlier steps in this function. Whether the callees undo anything is not in this packet.

Both `limit exceeded` refusals leave stale stack words at `+0xa` to `+0xf` and `+0x28` onward of the result, and `T` at `+0x20`. Nothing decodes them for this tag as far as this packet shows, and the rule list holds them to the stack fill.

### Lengths

`0x3c00f50` (slot `0x5774c38`) takes a name and a text: name `<= 100`, text `<= 2000`, both inclusive, else tag `0x143` with the length, name first. Both strings are freed on refusal. The text steps `0x3729ca0` and `0x3729830` use the same 2000 and refuse with tag `0x140` for an unknown id, then swap the text in place: question record `+0x20`, outcome record `+0x70`.

### Settlement

Wrapper `0x274b290` takes `x` as `f64`:

```
refuse "invalid settlement price" unless x is -0.0, +0.0, or a positive value <= 1.0
gate 0x3729df0 returns None, Some(fallback), or a refusal
settle(outcome, x, details)
if Some(fallback) and the first call returned 0x27: settle(fallback, 0.0, empty details)
if the last call returned 0x27: done
else S+0x1e8 = 1; record 4 at impl_outcome.rs:347:50; if user != 0, add user to the set; refuse tag 0x140
```

`0x27` is the only success value. The set is `S + 0x8b8`, or `S + 0x1338` in `0x4d69820`. The sticky word is what the prelude reads, so one failed settlement stops every later `OutcomeDeploy` with status 7. No function in this packet clears it.

Gate `0x3729df0`:

```
outcome not in T+0xa0                 Ok(None), any fraction in the wrapper's range
question of the link missing          status 8
record +0x38 (fallback) == outcome    text "cannot settle fallback outcome"
x == 0                                Ok(None)
x != 1                                text "question outcomes must be settled to exactly 0 or 1"
1 + named count != 2                  text "cannot settle to 1 until all other outcomes are settled to 0"
else                                  Ok(Some(fallback))
```

A standalone outcome can take any fraction in `[0, 1]`. A question outcome takes only 0 or 1. The named set at record `+0x40` must hold exactly one id, and the gate does not check that this id is the outcome being settled. The call collects `chain(once(fallback), set)` into a `Vec` and compares the length with 2.

### Question record

`0x3729990` (slot `0x5774c88`) takes a fallback and builds the record:

```
next = T+0x138; next > 9999 "limit exceeded"
next already a question     "invalid question"
fallback in T+0xa0          "invalid fallback outcome"
for side in 0, 1: circulation(fallback, side); lookup failure status 8; value != 0 status 9
```

Status 9 reads `Outcome already has supply`, so a fallback must have no circulating supply on either side when it becomes a fallback. `0x3719210` is that value: outcome record `+0x28` or `+0x50` gives the token, `supply` comes from the map at spot `+0x388`, and the held row is the balance of the system address `0x32, 0 x 11, token big endian`:

```
missing outcome code 4; token not in supply code 0x16; held > supply code 0x12; else supply - held (held 0 with no row)
```

`0x3728c20` inserts the record, links the fallback to the question and adds one to `T+0x138`, saturating. `0x398cb60` returns the side names `Yes` and `No` for a question's outcomes.

### Duplicate scans

`0x372a910` walks all question ids and refuses `duplicate question` when name and text both match. `0x372aea0` walks all outcome ids, skips any id linked to a question, and refuses `duplicate standalone outcome` on the same test. A question outcome may therefore share its name and text with a standalone one. Both compare by length first, then bytes.

## Implementation and comparison

not yet implemented. Comparison with the reference:

| Point | Reference | Bytes |
|---|---|---|
| Action | no `OutcomeDeploy` type | ten arms, `arms.tsv` |
| Price validity | `is_finite` and `0..=1` | same set, `-0.0` admitted, written as a bit test plus `ucomisd` |
| Second settle | `link.kind == Paired`, then `settle_market_side(.., 0.0)` | same shape, and the guard is the gate's `Some` |
| Failure | `result_from_internal_status` | sticky `S+0x1e8`, status 7 on every later action, tag `0x140` here |
| Exact 0 or 1, one remaining | not present | gate above |

The Location in the wrapper names `l1/src/exchange/impl_outcome.rs`, so the reference's file name agrees (`locations.tsv`).

## Results and limitations

- 456 named cases and 400 seeded vectors run the real bytes of the 16 functions (5988 instructions). A separately written rule list predicts the whole heap image, the event list and the result of each. All match.
- Mutation: every reached conditional, immediate and field displacement in 14 functions, plus the one differing row of the two handler copies. 1173 mutants, 1069 killed, 104 survived. `mutations.tsv` gives each survivor a label. 25 are marked `same` (equal output by reading the row), and 79 are marked `gap`: those are weak spots in the fixtures, mostly hash probe steps and the key tree walk in the duplicate scans, so these rows are not proved by mutation. The labels were assigned from the row, not by a run that shows equivalence. An unedited image passes under the same step limit first, and each mutant runs only the cases that reach its row.
- 55 unit tests, with corrupted hash, last byte flip, out of range addresses and byte edits as negative controls.

Inferences, not observations:

- Arm 7 is named `RegisterQuestion` from its shape. The variant name list at `strings.tsv` holds nine of the ten names in order and leaves a gap there, and the `struct variant` text with 2 elements exists. Other arm names follow that order and agree with the element counts in `arms.tsv`.
- Chain byte 3 as Mainnet and 2 as Testnet is a reading from other packets, not from these functions.
- The meanings of `S+0x1c0` and `S+0x1d8` come from how they are compared.
- Rows in `Vec` collection helpers `0x3bae4b0` and the key collectors are stubs. The stub reads the iterator words and returns their count. That the real helper counts the same way was read from its first rows, not run.

Unresolved:

- Who resets the daily word, and who clears `S+0x1e8`, if anything does.
- The settle body and the `SettleQuestion` body (the rule behind `question settlement must have a winner` and `must include all remaining outcomes`) are out of scope here.
- Whether arm 2's word is bounded in the deploy call.
- Field names of `OutcomeTracker`.

Reachability of rows: landing pads, the eight-at-a-time tree descent loops, the zero-count walk in `0x372a910` and allocation failures in `0x398cb60` are not reached; `evidence.json` lists every unreached row. `0x4d66400` and `0x4d67e10` run 31 cases each and rely on the byte comparison for the rest.

Next question: what does `SettleQuestion` do to the same gate rules, and which step writes the daily word?
