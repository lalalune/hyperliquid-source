# RE-017: L1 quorum field from state loading to selected output writers

The `lhvt` field can be reconstructed through its absent-field default, nested JSON checks, 96-byte state handoff, and selected snapshot and app-hash writers, including the distinct optional `hsc` rule.

- Component ID: `abci`, bounded RE-017 extension for one L1 quorum field.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was a lead only and is not copied.
- Claim status: the byte-level observations are separated from conditional dataflow and type inferences below; runtime behavior and full component coverage are unresolved.
- Scope included and excluded: the selected `lhvt` JSON branch and its defaults, tracker and quorum value readers, copy lanes, and named binary, JSON and app-hash writer paths. Previously researched loader, outer visitor, materializer, action, block and hash-builder functions are boundary context, not newly owned functions. This does not cover the MessagePack reader, all state fields, complete begin/action/end-block execution, node #115, or visor.

## Reproduce

From the repository root with node #94 present, Python 3.12.3 on Linux x86-64, and the existing `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/abci_l1_quorum94.py --out research/work-items/RE-017-l1-quorum-handoff-94
python3 -m unittest tests.test_abci_l1_quorum94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-017-l1-quorum-handoff-94 && sha256sum -c MANIFEST.sha256)
```

For the independent comparison replace the placeholders with two different writable directories before running:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_l1_quorum94.py --out <first-output>
PYTHONHASHSEED=119 TZ=Pacific/Honolulu python3 tools/abci_l1_quorum94.py --out <second-output>
diff -r <first-output> <second-output>
for file in <first-output>/*; do cmp "$file" research/work-items/RE-017-l1-quorum-handoff-94/"${file##*/}"; done
```

The generator authenticates the full target digest first, reads the ELF as data, and writes the generated evidence only. It uses the shared section and FDE parsers, excludes `SHT_NOBITS`, interprets selected fixed instruction forms, and decodes RELA records directly. It does not invoke a disassembler or any external process; the focused tests have the same restriction and do not skip when the artifact is absent. GNU objdump 2.42 was used only for human inspection. No timestamp, host path, or normalization mask is put into the generated records. `MANIFEST.sha256` covers this README and all generated evidence in this directory.

## Evidence

All addresses below are linked ELF virtual addresses (load base zero); `functions.tsv`, `windows.tsv`, and the relocation tables also include file coordinates. FDE ends are exclusive. The 22 selected ranges are checked against actual `.eh_frame` records and the unwind index, and their whole file-backed bodies are retained with hashes. An FDE does not by itself prove all function boundaries. The 75 windows and selected branch/call tables are deliberately bounded; they are not an instruction census or a component denominator.

### Entry and prior boundaries

Prior `RE-017-abci-state-link-94` ties the `state.rs:107` Location to `0x3273810`: a call to `0x3c155a0` precedes a tag-2 return or an indirect call to the materializer. Prior `RE-019-rmp-json-loader-94` describes the JSON arm through `0x2fe2fe0`; `RE-009-abci-json-exchange-94` describes its `AbciStateDe`/`exchange` visitor and field tag. Those paths and their earlier GOT sites are not re-owned here. At the boundary in this packet, the Exchange visitor calls `0x31210a0` at `0x2fe73a8`; the selected value is the previously identified `lhvt` field.

| Selected role | Start VA | Observation |
| --- | --- | --- |
| `lhvt` value reader | `0x31210a0` | Object names `tracker`, `quorum_l1_hashes`, `highest_quorum_height`; also has a sequence route. |
| Tracker adapter and reader | `0x3b45940`, `0x31a1020` | The object route passes to the tracker reader; its first field classifier is `0x3008770`. |
| `hsc` value reader | `0x30e7140` | The selected object route checks keys `q` and `i` and calls `0x3087600` for each. |
| Quorum list and row | `0x308d1a0`, `0x340f760`, `0x303eaa0`, `0x31888c0` | List reader, 88-byte collection loop, pair reader, and nested row-value reader. |
| Absent-field initializer | `0x3a054e0` | Builds a 96-byte default on successful three-byte allocation. |
| Low writer and children | `0x1e84d50`, `0x2326ea0`, `0x1e43a90`, `0x1de0be0`, `0x1e84540`, `0x1e84a50` | Named record, tracker, list, pair and row-value output. |
| Shared writer | `0x48c8ba0`, `0x48c2af0`, `0x440a800` | Separate selected implementation with matching top-level field names and offsets. |
| Snapshot field wrappers | `0x27b29c0`, `0x27af200`, `0x1e84ee0` | Field name `lhvt` and selected binary and JSON output branches. |

The prior action-87 packet `bridge-l1-hash-votes-94` independently reports a quorum result updating this state field, appending a row and pruning lower tracker heights; it identifies `0x2761b20` taking and resetting the list. Those are prior-work boundaries, not new evidence that a particular block or loader instance ran. The available static bytes do not prove scheduling or that a later writer sees the same object without intervening mutation.

### JSON objects and failure branches

`keys.tsv` reconstructs each outer and row key from the actual compared words or overlapping SIMD fragments. A duplicate after a successful first value follows the indicated selected guard. Object completion checks the missing fields in the order shown; this is not a claim about every malformed-input error precedence.

| Object | Field, in completion-check order | Duplicate target VA |
| --- | --- | --- |
| `lhvt` | `tracker` | `0x312260a` |
| `lhvt` | `quorum_l1_hashes` | `0x3122599` |
| `lhvt` | `highest_quorum_height` | `0x3122683` |
| Quorum row value | `l1_hash` | `0x3189a09` |
| Quorum row value | `hot_user_to_signature` | `0x3189a79` |
| Quorum row value | `hard_voter_to_signature` | `0x3189ae9` |

For the tracker, `tracker-keys.tsv` and `tracker-tables.tsv` bind `name`, `hsc`, and `i` to two dispatch tables, before and after a successful `i` value. The selected completion route checks `name` then `i`. Unlike those required fields, an omitted `hsc` is permitted: a flag-derived SIMD mask at `0x31a1d4d` clears both 8-byte `hsc` words when its presence flag is zero. When the flag is one it retains the child words. A repeated `i` after its first successful value takes `0x31a1c8f`; the name and `hsc` guards have separate targets before and after `i`. The eight rows of `tracker-cases.tsv` are a model of those completion checks, not target executions.

When an `hsc` object is present, its selected reader compares one-byte keys `q` and `i`, calls the same numeric child for each, and checks `q` before `i` at completion. Successful `q` and `i` occupy payload offsets `0` and `8`; duplicate and missing targets are in `hsc-fields.tsv`. This does not establish the accepted numeric grammar. The four rows of `hsc-cases.tsv` model only these checks; `diagnostics.tsv` binds the selected tracker and `hsc` error names to literal bytes, while `diagnostic-templates.tsv` checks their missing and duplicate format descriptors. Unknown keys take a separate helper path whose complete semantics are not claimed.

The list route reads pairs consisting of a height and a row value. The collection, cleanup and low/shared writer loops all expose stride `0x58`; row value members are reached at offsets `0`, `0x20` and `0x38` from the value after the height. On selected child failures the list paths enter cleanup of accumulated rows and their backing allocation. The exact accepted JSON language, map ordering and all helper failures remain open.

### Absent field and 96-byte handoff

The visitor's comparison at `0x2ff360e` selects an initializer when its local field word equals the absent sentinel. The indirect site `0x2ff3618` addresses slot `0x5770e30`; the selected type-8 RELATIVE record resolves it to `0x3a054e0`. This is a distinct slot from the pre-existing RE-017 loader and materializer GOT slots.

On its returning allocation path, the initializer stores bytes `lhv` into the allocated three-byte buffer and initializes the following words. `default-layout.tsv` retains every offset and store site; the symbolic pointer and unspecified stack word are intentional.

| Offsets from initialized field | Selected stores |
| --- | --- |
| `0x00`, `0x08`, `0x10` | `3`, allocated pointer, `3`; the allocated literal is `lhv`. |
| `0x18`, `0x20` | Both words zero. |
| `0x28`, `0x30`, `0x38` | Zero, an unspecified copied stack word, zero. |
| `0x40`, `0x48`, `0x50`, `0x58` | `0`, `8`, `0`, `0`. |

The middle tracker word is not initialized by the selected instructions and must not be represented as zero. A null allocation result branches at `0x3a05508` to the handler call at `0x3a05566`; `ud2` follows if that call returns. The allocation and failure-handler roles are inferences from the arguments, null test and stores; their full contracts and the handler's outcome are not established.

On the selected present-value route, six 16-byte lanes move from visitor stack `+0x1fd0` to `+0x2100`, and six more move to output-base `+0x1a90..+0x1aef`. The absent-field initializer writes directly to that same local destination before this output copy. At the prior materializer boundary, six matched lanes load input-base `+0x1a90..+0x1aef` and store output-base `+0x35b0..+0x360f`. `transfers.tsv` checks all source and destination displacements and vector registers. Treating these as one continuous field requires the selected success routes, matching input/output buffer identity, standard register preservation, and no intervening writes or aliases; those conditions are not an observed execution trace.

### Selected output and root-input boundary

The prior state writers pass state `+0x35b0` to the two newly selected wrappers. The binary wrapper emits the enclosing name `lhvt` when its name mode requires it, then transfers to `0x1e84d50`; a failed name write takes its tagged result path. The JSON wrapper passes the same name and field to `0x1e84ee0`, which writes braces on its selected normal path. Both writer families select the same ordered fields and offsets:

| Field | Offset from `lhvt` | Selected low child |
| --- | --- | --- |
| `tracker` | `0x00` | `0x2326ea0` |
| `quorum_l1_hashes` | `0x40` | `0x1e43a90` |
| `highest_quorum_height` | `0x58` | `0x25ac0d0` |

The low tracker writer accesses `name` at `+0x08`, `hsc` at `+0x18`, and `i` at `+0x28`. Its `hsc` and `i` children remain boundary helpers. The nested quorum writer uses `l1_hash`, `hot_user_to_signature`, and `hard_voter_to_signature` at the offsets above. In the direct row writer, the selected mode byte values 0 and 1 compute header bytes `0x93` and `0x83`, respectively; these synthetic cases do not establish which mode occurs at every caller. Header, field-name and child-result failures follow separate checked branches. The writer's count high-word test and boundary examples are retained without inferring that every large count fails.

Prior `RE-009-app-hash-builder-94` identifies low and shared descriptor row 36. The low builder's selected boundary snippets pass its second argument through stack `+0x208` to the state base, box state `+0x35b0`, and pair that box register with descriptor `0x56bdeb8`; its relocated slot `0x56bded0` reaches the prior closure and then the low writer. The matching shared row reaches `0x48c8ba0`. Both closure windows set the writer byte at `+0x0b` to 1 and the byte at `+0x0c` to 0; the former selects the field-name calls in the top-level writers. The capture association assumes the saved stack slot and selected register value survive the intervening instructions and calls. `low-capture.tsv`, `hash-configs.tsv`, `descriptors.tsv`, and `relocations.tsv` preserve the selected operands, thunks and relocations. This establishes a candidate input to that prior hash construction under the stated object and control-flow assumptions; it does not recompute a root or prove whole-object identity between loader, action and hash builder.

`lsda-headers.tsv`, `lsda-rows.tsv`, and `lsda-calls.tsv` retain selected exception-table encodings and ranges. For example, the low list writer call at `0x1e43b49` falls in a row with landing `0x1e43cea` and action selector 0. These records do not determine personality behavior or all unwind outcomes.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo build, authorized target execution, snapshot fixture, digest comparison, normalized-byte mask, helper closure, vtable/data closure, or whole-ELF comparison has been measured. The generator retains raw selected body and instruction bytes without normalization. The focused tests include digest, actual FDE and body corruption, each selected branch and call displacement, literal and table mutation, missing and duplicate relocations, invalid/NOBITS/ambiguous mappings, the copy-register and offset chain, the default initializer, and synthetic presence and encoding boundary cases. These controls validate the extractor and bounded models, not a reconstructed node.

## Results and limitations

`summary.json` records 22 selected FDE ranges, 75 fixed windows, 226 conditional branches, 96 direct calls, 11 key fragments for six outer/row names, three tracker names in two dispatch tables, two `hsc` names, 15 writer fields, 18 copy lanes, two hash descriptors and three RELATIVE relocations. It also retains 11 selected LSDA headers and 191 selected LSDA rows. These are selected evidence counts, not estimates of total coverage. The focused suite passed 47 tests with zero skips; independent generations under different hash seeds and timezones matched byte for byte, and artifact verification and catalogue checking passed. Repository-wide unittest discovery was not run under the specified memory constraint.

No ABCI progress gate is requested. The MessagePack input reader, full object identity and aliasing, precise numeric parsing, map ordering, complete failure/unwind semantics, begin/action/end integration, actual file effects and the complete state-root preimage remain unresolved. Next question: can the MessagePack `lhvt` decode path and ownership across the post-load/action/hash transitions be established with separate unowned functions and an independently authored offline codec?
