# bridge: Bridge2 persisted msgpack form, both directions (node #94)

This packet fixes the exact msgpack bytes of the `Bridge2` state in both directions, so a Rust `Bridge2` can now be
written and read against real state: every map is an array of pairs, five of the ten fields are required, and four
of the five trackers are empty-by-type for hot voters (`hard_quorum_policy::NoVoter`).

- Component ID: `bridge` (path rules `l1/bridge2.rs`)
- Target release and full SHA-256: `hl-node` #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`; `references/can1357-hl` used only as a lead
- Claim status: observation, with inferences labelled; no gate requested
- Scope included and excluded: included are the msgpack field serializer `0x3797ba0`, its value writers, and the
  decoder `0x18761f0` with its two compiled copies. Excluded are the JSON writers `0x2215860`, `0x374b450`,
  `0x48f5e70`, the app hash writer, the file that holds the state, and any execution of the binary.

## Reproduce

Run from the repository root. Standard library only. No external program is called and the binary is never executed.

```sh
python3 tools/bridge_state_wire.py --out research/work-items/bridge-state-wire-94
python3 -m unittest tests.test_bridge_state_wire
```

The tool checks the artifact SHA-256 first and fails on a mismatch. Function bounds come from `.eh_frame` through the
shared parsers. All real bytes run in a small x86-64 interpreter in the tool, on fixture states with real B-tree nodes.
Output depends only on the artifact.

## Evidence

Coordinates are virtual addresses. Files beside this record:

| file | content |
| --- | --- |
| `fields.tsv` | the ten fields: index, text address, state offset, writer, decode rule, wire form |
| `trackers.tsv` | the five trackers: hsc, row key, status payload, vote key, vks and hvs rows |
| `path.tsv` | 33 named functions and their reached bytes |
| `function-rows.tsv` | every reached row of those functions |
| `scenarios.tsv` | every named case and its outcome |
| `wire-samples.tsv` | full bytes of one state in both forms |
| `copies.tsv` | decoder copies checked against the same rules |
| `key-rows.tsv` | the rows behind the main rules |
| `texts.tsv` | text addresses, including the two type names |
| `mutations.tsv` | every byte edit and its outcome |

### Writing

- `0x3797ba0` writes the key `bridge2` only under the named flag at serializer `+0xb`, then a ten-field struct: a map
  with keys when the flag is set, an array without keys when it is clear.
- Field order on the wire is `fields.tsv` order. It is not the state offset order.
- Every B-tree map is written as an array of two-element arrays `[key, value]`, in tree order. Nothing sorts here.
  Sets are maps to unit, so a row is `[key, nil]`.
- A tracker is `{name, hsc, i}`. Only the deposit tracker has `hsc {q, i}`, both msgpack f64. The other four write
  `hsc` as an empty array even under the named flag.
- A row value is `{arq, qst, vts}`. `arq` is a bool. `qst` is the string `N`, or a one-key map `{Q: payload}` in both
  forms. `vts` is an array of `[key, {vks, hvs}]`.
- The payload and the vote key follow the tracker: `{user, usd}`, `{destination, usd}`, a 32-byte hash, or nil.
- `vks` rows hold a 32-byte key as hex. The signature trackers carry `{r, s, v}`: `r` and `s` are 32-byte little-endian
  words printed as `0x` hex with no leading zeros, and `v` is one compact byte.
- Times are text from a 12-byte value (packed date, seconds, nanoseconds). The fraction takes 0, 3, 6 or 9 digits. A
  fraction of 1e9 or more prints second 60. Years outside 0..9999 take a sign. There is no zone mark.
- `0x3615fa0` walks `hvs` of the four non-deposit trackers. A non-empty map stops in a nounwind panic with the text
  ``attempted to instantiate uninhabited type `hard_quorum_policy::NoVoter` ``. The real `hvs` set exists only for deposits.

### Reading

- `0x18761f0` takes a map, or an array of at least 7 entries. An array of 11 is a length error.
- Keys may be names or integer indexes 0..9. Unknown names and index 10 are skipped, with their value.
- Required: the five trackers. Absent `finished_deposits_data` and `finished_withdrawal_to_time` stay empty; `bal`,
  `last_pruned_deposit_block_number` stay 0; `oaw` stays false. A repeat of any key is ``duplicate field``.
- A short array reports the next required index, so an array of 1 reports length 2 and an array of 4 reports 5.
- Tracker rows are taken as an array of pairs or as a msgpack map. A repeated row key is the text `duplicate key`, in
  every map tested. Rows may arrive in any order and end up sorted by key type.
- Sort keys tested: `EthEventId` by `b`, `t`, `e`, `i`, `h`. `UserAndNonce` by user bytes then nonce. Vote keys by address
  then `usd`.
- `hsc` of the deposit tracker is optional and reads as zero. For the other four it is the unit struct
  `NoopHardQuorumPolicy`: nil or absent is taken, a map or a sequence is refused. `qst` is optional and reads as `N`.
- Hash and address text takes `0x` or no prefix and either case.

## Inferences

- `arq`, `qst`, `vts`, `vks`, `hvs` read as already-reached-quorum, quorum status, votes, validator keys and hot voters.
  The bytes prove their position and type, not those meanings.
- `hard_quorum_policy` looks like a generic parameter: a policy type with a voter type, where the deposit tracker has
  a real policy (`hsc`) and a real voter (20-byte address), and the rest take `NoopHardQuorumPolicy` and `NoVoter`.
- The reference has `EthEventId` with two fields and no tracker policy parameter. Both differ from the bytes.
- The optional fields look like `#[serde(default)]`, added after the first state format.

## Implementation and comparison

Not yet implemented. No Rust is added. A byte-exact implementation needs the rules above; `scenarios.tsv` and
`wire-samples.tsv` can serve as fixtures.

## Results and limitations

- 33 named functions, 3903 reached rows, 17906 of 27965 body bytes.
- 334 named cases (108 decode, 226 encode) and 115 generated cases: 0 mismatches. Every kept decode
  was fed back through the real serializer and compared. Every encode checks that nothing but the writer stays allocated.
- 2 decoder copies match the same rules on the light case set in `copies.tsv`.
- 190 sampled byte edits (one in 6 of condition and immediate rows): 148 killed, 42 survived,
  and survivors carry a class label only, they are not read one by one.
- Tests: 20 pass with negative controls for the digest, a misaligned address, an edited status immediate, a wrong
  rule, a wrong sort and stored files.

Limits:

- The rule list came after reading output, so it describes these cases; it is not an independent prediction.
- Refusal text for nested values is a table of observed text, not derived.
- The write error paths need a failing writer and are not run. Arrays over 65535 rows and lengths over `u32` are not run.
- Mode byte `+0xc` was tested at 0, 1, 2, but which value the node uses is not read here, nor is the caller `0x3753600`.
- Mutants skip the two `130_rows` cases to stay within the step limit.

Next question: which caller sets the named flag for `0x3753600`, and do the JSON writers `0x2215860`, `0x374b450`
agree with this field order.
