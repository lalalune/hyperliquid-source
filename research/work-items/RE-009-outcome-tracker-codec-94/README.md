# RE-009: outcome-tracker state codec and collection ordering

The node #94 outcome-tracker codec fixes the 13 serialized field names and their object offsets, and shows that the `tto` and `otq` collections use ascending unsigned keys on their small-input path, allowing a reconstruction to retain these fields and reproduce that part of their state serialization.

- Component ID: RE-009, storage and state roots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a lead.
- Claim status: observations are the selected instructions, field bytes, offsets, call targets, dispatch table, comparisons and error branches; codec labels, data-structure names and field meanings are inferences. The complete collection codecs, large-sort paths and snapshot compatibility are unresolved.
- Scope included and excluded: one parent `outr` field, the two selected outcome-tracker writers, one MessagePack-shaped reader's field classifier and duplicate arms, and five collection adapters, with the short sort and selected element writer for `tto` and `otq`. Excluded are a complete reader, the other three collection codecs, sorting at 21 or more items, the hash algorithm, runtime I/O, other releases and execution of the target.

## Reproduce

Run in the repository root with Python 3.12 and the standard library. The tool imports `tools/elf_index.py` and `tools/fde_extents.py`, validates the complete input digest before parsing, reads only file-backed ELF sections, and runs no external program. The interpreter only interprets the scoped classifier instruction encodings, never starts the node and performs no network or chain access. GNU objdump 2.42 was used separately for human inspection; its text is not an input or generated evidence.

```sh
python3 tools/artifacts.py verify
python3 tools/outcome_tracker_codec94.py --out research/work-items/RE-009-outcome-tracker-codec-94
python3 -m unittest tests.test_outcome_tracker_codec94
python3 tools/catalogue.py --check
(cd research/work-items/RE-009-outcome-tracker-codec-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC python3 tools/outcome_tracker_codec94.py --out work/outcome-codec-a
PYTHONHASHSEED=9 TZ=Pacific/Honolulu python3 tools/outcome_tracker_codec94.py --out work/outcome-codec-b
diff -r work/outcome-codec-a work/outcome-codec-b
```

`evidence.json` and `fields.tsv` are generated; the manifest covers these and this README. File hashes are in the manifest. Evidence uses ELF link-time virtual addresses, plus file offsets for the bounded windows. FDE end addresses are exclusive; an unwind extent is not alone a proof of source-function boundaries or of cold-part completeness. The tool checks the `.eh_frame_hdr` entry against the shared `.eh_frame` parser and hashes all 23 selected FDE bodies. Analysis is limited to these bodies and named sites, not a whole-node census.

## Evidence

### Parent and field order

The selected parent calls `0x23d7d00` at `0x2390e35` with the same object pointer. The wrapper emits four bytes `outr` in its named mode, then tail-jumps to `0x26d06d0`; an error emitting the outer name returns before that jump. The writer uses 13 for both its named and positional header helpers. A separate JSON-shaped writer at `0x26d0b30` passes the same names and offsets in the same order. These are individual static paths; the two writers are not claimed to have identical failure behavior.

| Order | Key | Input offset | Selected write shape |
| ---: | --- | --- | --- |
| 0 | `dga` | `+0x0` | dword discriminant; value 2 selects an inline `c0` byte, otherwise a child is called |
| 1 | `nou` | `+0x130` | qword passed to scalar helper |
| 2 | `nqu` | `+0x138` | qword passed to the same helper |
| 3 | `fs` | `+0x140` | eight-byte load into an XMM scalar register |
| 4 | `l` | `+0x158` | byte passed to a child writer |
| 5 | `ndo` | `+0x148` | qword passed to a named scalar helper |
| 6 | `mut` | `+0x150` | qword passed to the same named scalar helper |
| 7 | `uoa` | `+0x159` | byte passed to a named helper; on byte values 0 and 1 its marker input is `c2` or `c3` |
| 8 | `utd` | `+0x40` | collection wrapper |
| 9 | `tto` | `+0x70` | collection wrapper |
| 10 | `otq` | `+0xa0` | collection wrapper |
| 11 | `ots` | `+0xd0` | collection wrapper |
| 12 | `qts` | `+0x100` | collection wrapper |

`fields.tsv` gives the actual key and load sites in each writer. The record also retains the body bytes around the parent, mode choice, discriminant, and marker decision. The header selects a map-shaped helper for nonzero mode and an array-shaped helper for zero mode. Individual key gates are not uniform for arbitrary mode bytes; only mode values 0 and 1 are interpreted as named and positional here. The evidence does not establish that either mode is used by a particular persisted snapshot.

### Collection adapters and short sort

The last five wrappers tail-jump to separate adapters. Each adapter calls a collector, then a second helper, then an output helper; `nested_adapters` records all 15 call sites and targets. For `tto` and `otq`, the second helpers are `0x1fec530` and `0x1fef560`. Their first 215 bytes are identical, including the count comparison with 21, a 16-byte record stride, pointer dereferences, and an unsigned key comparison. On this bounded branch, counts 0 and 1 return without reordering; counts 2 through 20 use a backward insertion loop. It moves an element when the next key is strictly smaller and leaves equal keys in their input order. The evidence supports ascending unsigned qword order for this branch; it does not analyze the branch for counts of 21 or more.

Both adapters then call `0x1e372f0`, which passes the collection count to a sequence-header helper and, on the selected item route, passes each 16-byte record's two pointers to `0x1de62f0`. On one route that child requests a two-element sequence and calls `0x1e0d400` for each pointer; the latter dereferences a qword before calling the shared scalar writer. The alternate serializer configuration and nested scalar writer's full encoding are outside the claim. The recorded model sample sorts `(3,a), (0,b), (3,c), (2,d)` to `(0,b), (2,d), (3,a), (3,c)`; it is a static model of the inspected loop, not an execution capture.

### Reader and failures

The reader also addresses a relocated pointer-length record at `0x5687ba8`; the RELATIVE relocation and stored length identify the exact diagnostic `struct OutcomeTracker with 13 elements`. The tool reads both the relocation and literal from the ELF and checks its count against the writer headers. At `0x17f3426` the selected reader calls the classifier `0x16e2850` for one string-key path. Its 14-entry dispatch has 13 field arms and an unknown arm. The tool interprets the classifier's actual instructions, including its relative jump table; every writer name yields its matching selector. The 13 field arms test their individual presence states before branching to the corresponding `duplicate field` template. The unknown arm calls a separate helper with argument 1; that helper is not analyzed.

When the map-completion branch is reached, an absent `fs` supplies all-zero 64-bit floating bits, and absent `ndo` and `mut` supply zero qwords. The reader arms and completion checks use the same presence-state locations. These defaults do not establish how malformed values are handled.

The reader also contains selected `missing field` diagnostic sites for `nou`, `nqu`, `utd`, `tto`, and `ots`. Their presence does not by itself establish the outcome of every absent-field case, the full sequence grammar or global error precedence. `evidence.json` records 18 MessagePack-shaped writer call/conditional-failure pairs and 13 JSON-shaped call/conditional-failure pairs. Each selected failure branch leaves the subsequent field path; this does not model allocation failures, cleanup, or failures inside the called helpers.

### Inferences and relationship to prior work

The relocated 13-element diagnostic motivates the type label; the binary does not provide a recovered Rust declaration. The `c0` byte is consistent with MessagePack nil, the two mode branches with map and array serialization, and the two byte markers with false and true. The scalar helpers' complete behavior is not recovered here.

The earlier [outcome deploy packet](../RE-004-outcome-deploy-action-94/README.md) assigns a candidate tracker base and interprets offsets `+0x130`, `+0x138`, `+0x148` and `+0xa0` as next outcome, next question, daily deployed count and outcome-to-question linkage. Their correspondence to `nou`, `nqu`, `ndo` and `otq` is an inference from offsets, labels and that packet, not a newly proven type identity. The [app-hash builder packet](../RE-009-app-hash-builder-94/README.md) establishes a state serialization and digest framework; joining every parent and the selected `outr` object to a specific hash input remains a separate question.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No compiler, binary comparison, normalization mask, runtime fixture or target execution is claimed. The limited classifier interpreter executes modeled instruction semantics over bytes read from the ELF, and the extractor separately resolves the reader dispatch table; the sort example is a separate bounded model rather than target execution. The tests attack a wrong input digest, rehashed mutations of code, a literal, and both jump tables, unsupported addresses and a NOBITS section, plus every single-byte substitution of the 13 keys. No other callee, relocation, vtable or whole-ELF closure is claimed.

## Results and limitations

The generated record contains 23 selected FDEs, 13 fields cross-checked across two writers and one reader's selected field-name evidence, 14 dispatch entries, 13 duplicate branches, five selected missing-field diagnostics, 18 and 13 writer failure branches, and five adapter call chains. The focused suite has 15 tests, including 9,180 single-byte key substitutions. These are selected-path counts, not node coverage or proof of correctness. No progress gate is requested.

The full encoding and defaults of most fields, the children behind `utd`, `ots` and `qts`, malformed or duplicate nested collection keys, the large-input sorting path, whole-record round trips, persistence format, and the exact connection of this record to each app-hash lane remain open. Next trace the collection emitter and sorter for 21 or more entries, then connect the enclosing object to a previously identified app-hash capture without duplicating existing function analysis.
