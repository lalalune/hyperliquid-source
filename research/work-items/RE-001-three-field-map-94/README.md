# RE-001: chainId/address/nonce prepared-map dispatch

- Component: serialization support. Question: which named fields, duplicate
  checks and output regions does seed `0x4674b50` actually use?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, consulted as an unlicensed lead.
- Status: captured byte-key/field/control observations and a conditional model.
  The original private type, protocol and caller remain unresolved.

The reference `node/stream_msg.rs` suggests a variadic ABCI greeting reducer at
this address. The captured key decoder and diagnostic field names instead
establish a map path with `chainId`, `address` and `nonce`. This packet does
not use the pending greeting name as a recovered protocol or wire-format fact.
It also does not assign another speculative transaction/signing type name.

## Reproduce

Repository root, CPython 3.12.14 on Windows:

```sh
python tools/three_field_map_static.py --out work/three-field-map-94.json
python -m unittest discover -s tests -p test_three_field_map_static.py -v
python research/work-items/RE-001-three-field-map-94/export_disassembly.py
```

Verifier/model/tests use the standard library. Optional export uses Capstone
5.0.6, x86-64 Intel syntax, inspected wheel SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
No captured code, network, signing or key access runs.

`windows.capstone.txt` retains complete FDE windows
`[0x4674b50,0x467538c)` (**2,108 bytes / 417 instructions**) and
`[0x4bd2c90,0x4bd2f16)` (**646 bytes / 173 instructions**). Total:
**2,754 bytes / 590 instructions**, with contiguous complete byte consumption,
raw original FDE/CIE records, body hashes and the field jump table. All selected
observations and dispatch targets are real instruction starts. Addresses are
unrelocated ELF VAs; `.text` offsets are VA minus `0x1000`. No masks.

## Captured byte-key and field observations

The byte-slice key path checks lengths 7 and 5 and compares bytes against
captured data `chainId` at `0x7041cd`, `address` at `0x7040a8`, and `nonce` at
`0x7041d4`. Seven-byte comparisons use overlapping 4+4-byte loads; the five-byte
case uses 4+1. Names are case-sensitive and length-sensitive. The decoder also
has other Content-tag/numeric/owned-value paths; these are exported but outside
the byte-key model. No claim that only string keys can reach the original helper.

On the selected key-success path, output byte 0 is 9 and byte 1 is the field ID.
The caller requires success byte 9 before dispatching via four signed relative
entries at `0x6f7024`:

| Field ID | Name | Dispatch | Presence/duplicate flag | Value helper |
| --- | --- | --- | --- | --- |
| 0 | chainId | `0x4674c8d` | `[RSP+0xb8]` | `0x4b7f180`, dword 1 takes its error arm |
| 1 | address | `0x4674da5` | `[RSP+0xb0]` | `0x4b78e80`, byte 9 takes its success arm |
| 2 | nonce | `0x4674d27` | `[RSP+0xa8]` | `0x4b7afa0`, byte 9 takes its success arm |
| 3 | other byte key | `0x4674d6b` | no named flag | consumes/drops a present value |

The prepared-item buffer and count are loaded from input offsets 8 and `0x10`.
The loop advances by 64 bytes; slot `0x57746b0 -> 0x4eb8d00` supplies its
per-item state. Result tag 22 follows a skip/continue path. Recognized duplicate
checks precede their value helpers and lead to field-specific duplicate
diagnostics. Unknown keys with present values do not set these three flags.
Absent values and helper failures have additional paths outside the model.

After successful named-value helpers, the normal result stores outer qword tag
0, 32 bytes for field 0 at `[8,40)`, 8 bytes for field 2 at `[40,48)`, and
20 bytes for field 1 at `[48,68)`. Those are captured copy regions, not proof
of their full Rust types or portable enum ABI.

Missing chainId enters its field diagnostic path directly. Missing address and
nonce involve additional helper calls with conditional tag checks. This packet
does **not** declare all three unconditionally required or invent their defaults
without closing those callees. The model reports the first selected missing
path/helper entry, not its ultimate success/error outcome.

## Conditional comparison and controls

The model takes prepared byte keys with **present values, successful key/value
helpers and ordinary drop returns**. It models recognized duplicate selection,
unknown-key omission from flags, missing-path ordering and a success candidate
when all named flags are set. It does not parse JSON/bincode or model values.

Six focused methods pass. **4,864** one-byte key substitutions (19 positions x
256 bytes) agree with an independent exact-key lookup. The population includes
raw non-UTF-8 byte slices and is not described as valid JSON keys. **5,461**
prepared key sequences over the three names and one unknown symbol, lengths
0..6, agree with an independent first-duplicate/missing-path form. All six
permutations containing each known key once reach the model's success candidate.
These are primitive/conditional comparisons, not captured executions or full
deserializer equivalence.

Actual-capture corruptions cover stride/skip tags, duplicate flags, presence
checks, output stores, signed table entries, helper calls, key constants,
diagnostic field bindings, FDE extent and identity. Both full bodies are hashed.
Make is absent, so required Makefile Python commands were run directly. Full
suite: **363 tests in 109.017 seconds; 7 failures, 16 errors, 21 skips**. All six
new methods pass. This independent main-based branch excludes unmerged #227.
Doctor reports missing native prerequisites. Eight artifact size/digest checks
pass before missing GPG stops signature verification. Imports reject the Windows
reference checkout (reserved `node/aux.rs`, hydrated LFS inputs retained);
catalogue fails on native backslash paths. Reproduce stops at artifact
verification. These failures are not marked passed.

No imported source, caller closure, value codec, full Content/Rust type,
protocol/wire/signing policy, native build/equivalence, hosted CI or progress gate.
Next question: close the item/value/missing-field helpers and actual callers
before assigning a complete typed deserializer or protocol name.
