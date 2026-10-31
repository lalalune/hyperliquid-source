# bridge: Bridge2 pretty JSON form and the state file route that picks it (node #94)

This packet fixes the exact pretty JSON text of the `Bridge2` state and the file route that chooses it, so a Rust state
writer can now be compared byte for byte: a path whose extension is `rmp` in any letter case gets named msgpack, every
other path except `/dev/null` gets JSON with two space indent, and the JSON keeps the msgpack field order but writes
`hsc` as `null` for four trackers and turns NaN and infinity into `null`.

- Component ID: `bridge` (path rules `l1/bridge2.rs`)
- Target release and full SHA-256: `hl-node` #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`; `references/can1357-hl` used only as a lead
- Claim status: observation, with inferences labelled; no gate requested
- Scope included and excluded: included are the JSON struct writer `0x2215860`, its field wrapper `0x27affa0`, the
  tracker, row, vote, status, key and tree walk writers under it, the compiled copies `0x374b450` and `0x48f5e70`, and
  the file routes `0x28eb1e0`, `0x3c165b0`. Excluded are the Exchange level JSON bodies beyond the `bridge2` field, the
  msgpack bodies (a stub here), the file steps through slots `0x576ea68` and `0x576f670` (stubs here), any JSON reader,
  and any execution of the binary.

## Reproduce

Run from the repository root. Standard library only. No external program is called and the binary is never executed.

```sh
python3 tools/bridge_state_json.py --out research/work-items/bridge-state-json-94
python3 -m unittest tests.test_bridge_state_json
```

The tool checks the artifact SHA-256 first and fails on a mismatch. Function bounds come from `.eh_frame` through the
shared parsers. All real bytes run in a small x86-64 interpreter in the tool, on fixture states with real B-tree nodes.
Output depends only on the artifact.

## Evidence

Coordinates are virtual addresses. Files beside this record:

| file | content |
| --- | --- |
| `fields.tsv` | the ten fields: index, text address, state offset, writer, JSON form |
| `path.tsv` | 67 named functions and their reached bytes |
| `function-rows.tsv` | every reached row of those functions |
| `scenarios.tsv` | every named case and its outcome |
| `sample-full.json` | the real text for one full state |
| `float-text.tsv` | the real text of 20 f64 bit patterns |
| `file-forms.tsv` | each path, both routes, and what ran |
| `call-chain.tsv` | call sites from the routes down to each copy, each checked as a real rel32 call |
| `copies.tsv` | compiled copies checked against the same rules |
| `key-rows.tsv` | the rows behind the main rules |
| `texts.tsv` | text addresses |
| `mutations.tsv` | every byte edit and its outcome |

### Route

`0x28eb1e0` and its twin `0x3c165b0` take a state pointer, a path and a fourth word:

| path | what runs |
| --- | --- |
| exactly `/dev/null` (9 bytes) | nothing; result 0, before any serializing |
| extension equals `rmp` under ASCII case folding | `0x2206f00`, then the two file steps |
| anything else, including no extension | pretty JSON through `0x2206ff0`, then the two file steps |

- The extension test is slot `0x576f620`, which holds `0x144a3e0`. It is `Path` style: the last normal part, trailing
  `/` and `.` ignored, text after the last dot. `.rmp` has no extension and takes JSON. `..rmp` has one and takes
  msgpack. `a.rmp/..` takes JSON. `a.rmp/.` takes msgpack. `/dev/null.rmp` takes msgpack, `/dev/nulL` takes JSON
  (`file-forms.tsv`).
- JSON: buffer 0x80 bytes, indent `"  "` from `0x3f5ff0`, level 0, has_value 0 (`0x28eb2a8` to `0x28eb2fb`).
- msgpack: empty buffer, options word `0x01000400` at `0x28eb25e`, so serializer byte `+0xb`, the named flag, is 1 and
  `+0xc` is 0. This answers which form these routes write: named, not array.
- Both forms open with one key `exchange` (`0x2206f77`, `0x2207044`), so in the file `bridge2` sits two levels down.
- A failed body goes to `0x28eb900` (JSON) or `0x28eb970` (msgpack) and skips both file steps. A nonzero result from
  the first file step skips the second. The buffer is freed on every path (the run checks that no block stays live).
- `call-chain.tsv` ties the routes and the two `state.rs` line 145 bodies to the three JSON copies: `0x28eb1e0` to
  `0x2215860`, `0x3c165b0` to `0x374b450`, and `0x46cea60`, `0x46cfe90` to `0x48f5e70`.

### JSON text

`0x2215860` takes the state and a serializer: `+0` the output vector, `+8` and `+0x10` indent text and size, `+0x18`
level, `+0x20` has_value. It raises the level, and every key goes through `0x2974190`.

- Field order is `fields.tsv` order, the same as msgpack. It is not state offset order.
- Layout: `{`, line feed, indent times level, `"key": value`, `,` and line feed between entries, line feed, closing indent,
  `}`. An empty array is `[]`.
- Every B-tree map is an array of two-element arrays `[key, value]` in tree order, as in msgpack. Sets are `[key, null]`.
  No JSON object has a data key, so nothing needs a text form of a key.
- A tracker is `{name, hsc, i}`. `hsc` of the deposit tracker is `{q, i}`. The other four write `null` through
  `0x2961580`, where msgpack writes an empty array. Same value, different unit form.
- A row value is `{arq, qst, vts}`. `qst` is `"N"` or a one-key object `{"Q": payload}`, and for validator set rows
  `{"Q": null}`.
- Numbers are plain decimal for `u64` up to `18446744073709551615`. There is no quoting of large values.
- f64 `q` and `i`: `float-text.tsv`. NaN and both infinities print `null`, so they do not survive a JSON round trip.
  Negative zero prints `-0.0`. A whole number under 1e16 prints with `.0`. From 1e16 up the form is `1e16`, with no plus
  sign and no fraction when one digit is enough. Small values stay plain down to `0.00001` and then use `1e-6`.
- Hashes and addresses are lower case `0x` hex at full width. `r` and `s` are `0x` hex with no leading
  zeros, `v` a number.
- Times are the same text as msgpack, with no zone mark. A fraction of 1e9 or more prints second 60.
- A name goes through `0x28c5220`: quote, backslash and the short escapes `\b \t \n \f \r`, `\u00xx` in lower case hex for
  other bytes under 0x20. Byte 0x7f and multi-byte UTF-8 pass as they are.
- `hvs` of the four non-deposit trackers stops in a nounwind panic when not empty. The text in `0x2215860` and
  `0x48f5e70` names ``l1::hard_quorum_policy::NoVoter``; `0x374b450` names ``hard_quorum_policy::NoVoter`` (`copies.tsv`).
- `0x27affa0` writes `bridge2` as a key of an open object: line feed for a first key, comma and line feed for a later one.

## Inferences

- `0x576ea68` looks like a parent folder step and `0x576f670` a write through a temp file: the body at `0x144c560` holds
  the text `fu_write_string_to_file_tmp/`. Both are stubs here, so that is not shown.
- The three copies look like one generic body compiled in three crates.
- JSON is presumably for reading by people: `0x2206f00` and the JSON body take the same state, and the `.rmp` dump paths
  named in `RE-009-storage-state-roots` take the msgpack arm by this rule.
- `null` for the no-op policy is what a unit struct gives in serde JSON. The name of that type comes from the msgpack
  packet, not from these bytes.

## Implementation and comparison

Not yet implemented. No Rust is added. `sample-full.json`, `scenarios.tsv` and `float-text.tsv` can serve as fixtures for
a byte-exact writer.

## Results and limitations

- 67 named functions, 6811 reached rows, 25857 of 41039 body bytes.
- 232 named cases and 60 generated cases: 0 mismatches against the rule list, which predicts every output
  character and each route's event list. Each JSON run also checks the level returns and only the writer stays allocated.
- 2 compiled copies match the same rules on `copies.tsv` cases, apart from the panic text above.
- 921 sampled byte edits (one in 2 of condition and immediate rows): 664 killed, 257 survived.
  Survivors carry a class label only, they are not read one by one.
- Tests: 23 pass with negative controls for the digest, a misaligned address, an edited immediate, a flipped branch,
  a wrong rule, a wrong chain target and stored files.

Limits:

- The rule list came after reading output, so it describes these cases; it is not an independent prediction.
- Writing to a vector cannot fail, so the error returns of the JSON writers are not run. A failing body is a stub result.
- Helpers already listed by other packets run for real and are not named targets, among them the row pair writers at
  `0x2908c50`, `0x2918420`, `0x291fe90`, `0x2920b40`, `0x2923a20`, `0x293a510`, `0x293abd0`, `0x2951e50`, the event
  writers `0x2215f00`, `0x2216c90`, and `0x144a3e0`. So edits do not cover them.
- The body at `0x46cea60` is not run, only its call into the JSON chain is checked.
- No JSON reader is pinned, so whether the node reads this text back is not shown.
- Mutants skip the `130_rows` case to stay within the step limit.
- Paths in the fixtures are UTF-8.

Next question: which callers pass which path into `0x28eb1e0` and `0x3c165b0`, and does a JSON state reader exist.
