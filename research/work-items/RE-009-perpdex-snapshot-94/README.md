# RE-009: PerpDex snapshot reader path

The node #94 snapshot reader requires `books`, `funding_tracker`, and `twap_tracker` in each `PerpDex` record and clears stored words when `perp_to_annotation` is absent; matching writers omit that fourth field when its count is zero, establishing a concrete compatibility decision for reconstruction.

- Component ID: RE-009, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` is a lead only.
- Claim status: observations for recorded bytes, tables, selected branches and calls; inference for the reader and compatibility interpretation; unresolved for the nested field types and live usage.
- Scope included and excluded: selected `PerpDexs` sequence and `PerpDex` record reading, field classification, missing/duplicate decisions, two separately located record writers, and selected failure and default paths. Excludes individual field codecs, complete MessagePack marker grammar, all input configurations, actual snapshot files, other releases and node execution.

## Reproduce

Run from the repository root, using Python 3.12.3 and the standard library with the existing `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/artifacts.py verify
python3 tools/perpdex_snapshot94.py --out work/perpdex-snapshot-check
python3 -m unittest tests.test_perpdex_snapshot94
cmp work/perpdex-snapshot-check/evidence.json research/work-items/RE-009-perpdex-snapshot-94/evidence.json
(cd research/work-items/RE-009-perpdex-snapshot-94 && sha256sum -c MANIFEST.sha256)
```

The generator checks the complete input SHA-256 first, then uses the shared ELF and FDE readers, rejects non-file-backed VA mappings, checks selected exact code windows, decodes calls, branches, key-comparison immediates and relative tables, and emits the raw selected bytes. It does not launch an external program. Its evidence has no operand normalization or masked bytes. GNU objdump 2.42 was used for manual inspection only. All addresses below are linked ELF virtual addresses; file offsets are recorded in `evidence.json`, and end addresses are exclusive. An FDE describes an unwind range and is not by itself proof of a complete original function boundary. No captured executable was run, and no network or chain data was accessed.

## Evidence

The existing state-wrapper packet establishes the outer snapshot reader and its nested exchange value. Within that nested value, a selected call at `0x1a54741` passes the eight literal bytes `PerpDexs` to `0x16bf310`. On the selected array route that function calls `0x24d17f0` at `0x16bfa94`; its loop calls the record reader `0x17a1540` at `0x24d18ae`. The record reader calls the byte-key classifier `0x16d1610` at `0x17a38d0`. These are four newly examined reader FDE ranges; the enclosing earlier reader is context, not a claim that all of its behavior was recovered.

| Function role | FDE range | Observed behavior |
| --- | --- | --- |
| Container dispatch | `0x16bf310..0x16bfdf5` | Selected array route checks and updates a 16-bit depth counter before and after the child. Zero, decrement-to-zero, and overflow checks have separate branches. |
| Sequence visitor | `0x24d17f0..0x24d1a8b` | Initial capacity is the smaller of input count and `0xd20`; each successful element occupies `0x138` bytes. Capacity exhaustion calls a growth helper. Element failure enters cleanup for previously constructed entries. The preallocation clamp is not an accepted-record limit. |
| Record visitor | `0x17a1540..0x17a4564` | Has selected positional and map routes. A successful record is copied in `0x138` bytes; failures and excess-element paths take separate routes. |
| Field classifier | `0x16d1610..0x16d17e7` | Length dispatch and byte comparisons return the four tags below; the other route produces tag 4. |
| Compact-shaped writer | `0x2443bd0..0x2443d8b` | Selects three or four output fields and dispatches named or positional headers. |
| JSON-shaped writer | `0x2443580..0x2443868` | Emits the same four names in order and skips the fourth when its count is zero. |

The classifier's 14-entry length table starts at `0x293b64`, indexing lengths 5 through 18. Its four admitted arms compare each name byte, with every mismatch reaching the unknown tag. The map visitor then uses the five-entry relative table at `0x2cbc58`:

| Tag | Name | Map target | Duplicate branch target |
| ---: | --- | --- | --- |
| 0 | `books` | `0x17a3ae9` | `0x17a4355` |
| 1 | `funding_tracker` | `0x17a3dee` | `0x17a440a` |
| 2 | `twap_tracker` | `0x17a3bdb` | `0x17a41ac` |
| 3 | `perp_to_annotation` | `0x17a3d04` | `0x17a425c` |
| 4 | unknown | `0x17a3b55` | not applicable |

Each duplicate branch reaches code that supplies the matching field string to a `duplicate field` diagnostic template; each initial field branch calls its respective child. Unknown-key handling calls a separate helper, whose complete behavior is not established. At map completion, the selected checks construct `missing field` diagnostics for `books`, then `funding_tracker`, then `twap_tracker` when their corresponding slots are absent. Once those have succeeded, the annotation presence bit controls conditional zeroing of its stored words at `0x17a2b7b..0x17a2bac`; it does not enter a missing-field diagnostic for that name on this path.

For the selected positional array route, count 0 goes to the first-element error; after successful preceding children, counts 1 and 2 route to errors for the next required element. At count 3, `0x17a2036` selects the zeroed fourth-field state; other counts reach the fourth child at `0x17a2114`. The post-child remainder check at `0x17a2265` copies the completed `0x138`-byte result when the remainder is zero and otherwise calls an error helper. Child failures, depth failures and the allocation failure route are not successful record outcomes. These count decisions are conditional on successful earlier child reads; they do not establish a complete encoded fixture.

### Independently located writers

The compact-shaped writer reads the word at input `+0x130` and uses `cmp`/`sbb` to pass a field count of 3 when it is zero and 4 otherwise. With serializer byte `+0xb` equal to 1 it selects a map-shaped header and passes the four name strings, in the table order, to the string helper; with byte 0 it selects an array-shaped header and omits field names. The corresponding value calls use input base offsets `+0`, `+0x48`, `+0x18`, and `+0x120`. The branch at `0x2443d0f` bypasses the fourth name and value when the word at `+0x130` is zero. Header, name and child errors route to a result propagation path before later fields are attempted. Values of the mode byte other than 0 and 1 are not characterized.

The JSON-shaped writer independently references the same four names and value offsets; its branch at `0x244370a` skips the fourth pair when the word at `+0x130` is zero. The matching names, order, field offsets and omission condition support identifying the writers with the reader's record; the binary evidence does not prove which snapshot entry point calls either writer. Neither writer's nested value representation is recovered here.

Inference: the four literal names, the sequence visitor and the missing/duplicate diagnostic setup identify a four-field `PerpDex` snapshot record, with the fourth field taking a default path for compatibility. The precise Rust types, source-level declaration, storage ownership of the nested values, and whether a particular production snapshot invokes this route remain unresolved. The `0xd20` value is only the initial allocation cap: the later growth call prevents treating it as a maximum accepted number of records.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Compiled comparison, masks, helper closure, execution against real fixtures and runtime behavior are not yet measured. The nine focused unittest methods cover the pinned six ranges, four field arms, four direct calls, 12 branch destinations and five map-table targets, as well as corrupted digest, rehashed changes to a reader branch, writer branch, comparison byte and table, changed literal, and out-of-range or malformed inputs. The 100 single-bit name mutations and eight length mutations test a model made from the extracted names; they are not target execution.

## Results and limitations

The extractor records six FDE ranges, 33 selected exact instruction windows, four direct calls, 12 selected conditional branches, four field names and five relative map targets. This is a bounded static route, not a complete function or snapshot census; no milestone gate is requested. Next question: recover and independently validate the nested values' codecs, then test complete synthetic snapshots in a separately authorized offline harness.
