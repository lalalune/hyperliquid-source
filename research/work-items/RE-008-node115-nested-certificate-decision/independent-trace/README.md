# Independent trace of the nested certificate flow

Two traces of node #115 (`artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`) were made by **a second model (OpenAI
GPT-6.1 via Codex CLI) given only inputs and the binary, without the Rust or expectations**. Both are static
(objdump / readelf); nothing was executed or emulated. The model files are kept as they were produced
(Korean, as the instructions asked); only the instruction files `SPEC.md` had an absolute path of the machine
the model ran on replaced by the repository-relative `artifacts/node/115/hl-node`.

This is a second reading of the same disassembly by a different model, not an execution of the target and not
a native differential run. It lowers the chance that one reader's slip survives; it does not exclude a slip
two readers share (see "What it does not show").

## What is here

| path | what |
| --- | --- |
| `xcheck1/SPEC.md` | the instructions the model got for run 1 |
| `xcheck1/inputs.tsv` | the 621 inputs (a projection of the input columns of `../cases.tsv`) |
| `xcheck1/TRACE.md`, `xcheck1/calculate_outputs.py`, `xcheck1/outputs.tsv` | its branch table, the script it wrote from that table and the 621 computed outputs |
| `xcheck1/RESULT.md` | the note written when run 1 was compared (against the round-1 corpus) |
| `xcheck2/SPEC.md` | the instructions for run 2 |
| `xcheck2/TRACE.md` | its stage-1 trace of the verifier, equality helper, collector, signature check, quorum and provider, written before it opened the packet, plus the correction it made in stage 2 (last section) |
| `xcheck2/DIFF.md` | its stage-2 comparison with the packet's relation tables |
| `xcheck2/compared/` | the relation tables and function list it compared (round-2 versions, SHA-256 `relations.tsv` `f1788efd…`, `relations-provider.tsv` `0013dbc0…`, `functions.tsv` `9a459e41…`) |
| `compare_trace.py`, `compare-result.txt`, `selftest-result.txt` | the normalizing comparison of run 1 with the current `../cases.tsv`, its result, and the result of its `--selftest` (baseline first, then 11 damages on either side, each reported for its own row and field). Needs `--outdir` (a new directory); the two result files are copies of its output |
| `xcheck3/QUESTION.md`, `ANSWER.md`, `COMPARE.md` | round 4: the question given to a Claude subagent for the digest builder and the recovery wrapper, its answer unchanged, and the author's comparison with the corpora |

## Run 1: the decision core `0x595fd20`

The model was given 621 inputs (word pairs, three words, a 32 byte tail, the context pair, and an assumed
result of the two callees: the verifier `0x595f880` and the equality helper `0x4e08870`) and had to compute
the output record tag and payload, whether each callee is called, and the reference record handed to the
helper. It wrote a branch table with instruction addresses and a script; the outputs come from the script.

Compared with the current `cases.tsv` (byte-identical to the round-1 file, `dc84c30f…`) by
`compare_trace.py`, which also checks that the input columns of `cases.tsv` are byte-identical to the
`inputs.tsv` the model was given:

| item | result |
| --- | --- |
| output tag | 621 / 621 equal |
| helper and verifier call counts | 621 / 621 equal |
| helper reference record (13 words) | 621 / 621 equal |
| payload words | 605 / 605 equal; 16 rows not compared (see N4) |
| rows differing after the notation normalization | 0 |

Normalizations, all notation: N1 hex in `cases.tsv` against decimal in the output; N2 the Rust model's
`DIVERGE` against the model's `noreturn`; N3 `fwd` ("the verifier's record is the output") checked against the
row's own `validator` input column (45 rows); N4 for the 16 `noreturn` rows (a verifier acceptance when the
pairs differ and the context is behind: the target makes a diagnostic call and does not return) the Rust model
carries the two pairs in `Output::Diverges` while the target writes nothing, so the payload column of those
rows is not compared (tag, call counts and reference still are, and agree). `--selftest` damages the expected
side seven ways (tag, call count, reference word, payload, `fwd` payload, id, one-sided `noreturn`) and each
is reported.

Things the model reported itself: the instructions said `a`..`e` are decimal but the file holds hex values
(it read hex; so does `cases.tsv`); the bytes of a tag `0x00` record beyond the four payload words and the
cleanup of a dropped verifier record with tags `0x10`/`0x13`/`0x20` (it assumed the drop completes) are not
determined by the inputs, so its outputs, like the Rust model, do not represent them.

The inputs were chosen by the author of the Rust, not by the second model: it checks the outputs for these
621 inputs, not that the inputs cover every path.

## Run 2: the new functions, `relations*.tsv` compared after the trace

Stage 1: from the bytes only, the model traced the verifier `0x595f880`, the equality helper `0x4e08870` and
`0x4e550e0`, the collector `0x4e00160`, the signature check `0x57e8bd0`, the quorum `0x595bc40` / `0x4d3e1a0`
and the provider `0x595e5c0` (`xcheck2/TRACE.md`). Stage 2: it then opened `relations.tsv`,
`relations-provider.tsv` and `functions.tsv` (the round-2 versions) and compared every row
(`xcheck2/DIFF.md`). The nine function ranges and byte hashes matched, 47 of the 50 relation rows were marked
as matching, and it reported three differences (one marked major):

| # | its finding | checked in the bytes by the author | handling |
| --- | --- | --- | --- |
| 1 (major) | `relations.tsv` V5 said the signature pointer handed to the per-entry check is entry + 0x18 for every entry. True for ring rows (`0x595fb50`); for a tree `0x513b200` returns the key address `leaf+0x320+20*i` in rax and the value address `leaf+8+72*i` in rdx (`0x513b3c1`..`0x513b3d3`) and the verifier passes that rdx on unchanged (`0x595fbf4`) | confirmed | V5 split into V5 / V5r / V5t, new row T1, new pinned functions `tree_next` and `signed_fold`; new corpus `../cases-tree.tsv` (43 rows, more than 64 signatures) and tests `tests/sigslot.rs`; four new mutants. No expected value of any existing case changed and no Rust logic line changed (the crate is value-level and already handed each entry its own signature); see `../ORACLE_FROZEN.txt` FREEZE 3 |
| 2 | V7 said "every entry passed (or the collection is empty)"; the whole-verifier result for an empty collection (tag `0x07` from the quorum, `0x28` first if the provider fails) was not stated | confirmed (`0x4e44c4d`..`0x4e44def`, `0x4d3e2e7`..`0x4d3e302`, `0x595bc5d`..`0x595bc65`, `0x595f903`..`0x595f9dd`) | V7 reworded; new rows F1 and V9 |
| 3 | Z2 said a zero fraction returns true "without reading any signer"; the stake test `0x4d3e1a0` runs first and walks the signer set | confirmed (`0x595bc57`..`0x595bc65`, `0x4d3e217`, `0x4e44c43`..`0x4e44c50`) | Z2 reworded to "skips the signer walk of Z3" |

Item 1 in context: the model's own stage-1 text had the same ring-only `+0x18` offset generalized to trees; it
traced `0x513b200` only while comparing with the packet and corrected its own text (last section of
`xcheck2/TRACE.md`). So for this point the independent reading is "found by the second model while diffing",
not "derived blind before it saw the packet's claim".

## Run 3 (round 4): the digest builder and the recovery wrapper, by a Claude subagent

Not the same kind of reader as runs 1 and 2: a Claude subagent (Anthropic, the same model family as the author,
fresh context) read `0x57e8d40` and `0x1536a90` with `objdump` and was told not to read the packet or the crate
(`xcheck3/QUESTION.md`; its answer is in `xcheck3/ANSWER.md`, unchanged). It was given the frame layout and the
addresses of the callees, from the author's reading, and asked for the exact bytes hashed for five frames and for
the behaviour of the recovery wrapper, without any expected value. The frames are rows of `cases-digest.tsv`
chosen by the author. Result (`xcheck3/COMPARE.md`): the five preimages are equal to the corpus rows, byte for
byte, and every point of its recovery-wrapper table (byte reversal of `r` and `s`, the recovery id for 13 values
of `v`, the three library entry points, the address slice, the two error kinds) is the packet's. Limits: same
disassembly, same model family, structure partly supplied, five frames, nothing run.

## What it does not show

- Both readings are of the same disassembly; the second model's stage-1 text made the same generalization
  that the packet's V5 made, so errors of one reader can be shared. No native run exists to settle a
  disagreement either way.
- Run 1 takes the callee results as given; it says nothing about the verifier's internals. Run 2 covers the
  paths its instructions named; the digest builder `0x57e8d40` and recovery (slot `0x64e0ad8`) were then a
  boundary and were not traced (run 3 traced them, with the limits above).
- Run 2's stage-2 comparison was against the round-2 relation tables. After the three corrections above the
  tables changed (`../ORACLE_FROZEN.txt`); the second model has not seen the corrected tables.
- The expected values of the new corpus `../cases-tree.tsv` come from the author's reference rules and were
  chosen after the finding; the second model did not compute them.
