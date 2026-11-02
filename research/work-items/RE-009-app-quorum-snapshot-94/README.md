# RE-009: app-hash vote tracker snapshot and hash-input path

Node #94 serializes the app-hash vote tracker as three ordered fields, with 64-byte in-memory quorum rows, three-field `r`/`s`/`v` signatures and a nested tracker whose `hsc` writer requests an empty sequence; the matching readers enforce field and row boundaries while their 16,384-row initial reservation is not an input-count limit.

- Component ID: RE-009, storage/state roots and state serialization.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `966865f1637a29ce75b019e1bf11d5529cc6f519` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference supplies leads only; no reference implementation is copied.
- Claim status: byte, call, branch, field reference, relocation and addressing observations are direct; names and the association with the previously mapped app-hash input are interpretations supported by the cited descriptors and prior work. Unresolved behavior is listed below.
- Scope included and excluded: the selected app-hash tracker writer and reader, nested tracker writer and part of its map reader, quorum-row sequence and pair writer/reader, quorum value writer/reader, signature-entry and signature-value writers, outer key classifier, and collection boundaries. Helpers outside the 18 selected FDEs are call boundaries, not newly analysed bodies. Excluded are the complete nested `i` entries, signature-map key and primitive encodings, collection ordering, all malformed-input paths, target execution and other releases.

## Reproduce

From the repository root, with Python 3.12.3, the standard library and the existing `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/artifacts.py verify
python3 tools/app_quorum_snapshot94.py --out research/work-items/RE-009-app-quorum-snapshot-94
python3 -m unittest tests.test_app_quorum_snapshot94
python3 tools/catalogue.py --check
(cd research/work-items/RE-009-app-quorum-snapshot-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC python3 tools/app_quorum_snapshot94.py --out <tmp-dir-a>
PYTHONHASHSEED=777 TZ=Pacific/Kiritimati python3 tools/app_quorum_snapshot94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

Replace the two placeholders with distinct fresh directories and compare their seven generated files with the corresponding files in this work item. The generator verifies the full binary SHA-256 before parsing, excludes `SHT_NOBITS` sections from file reads, and does not run the target or invoke any other program. `evidence.json`, `fields.tsv`, `calls.tsv`, `branches.tsv`, `key-comparisons.tsv`, `key-cases.tsv` and `reservation-cases.tsv` are generated; the README and manifest are not generated. The regeneration and focused tests were also run with binutils absent from `PATH`. GNU objdump 2.42 was used only for bounded human inspection; its output is not an input to the tool or tests. No normalization masks are used.

## Evidence

Coordinates are unrelocated ELF virtual addresses. FDE endpoints in `evidence.json` are exclusive and describe unwind ranges, not automatically complete control-flow boundaries. Selected full-extent hashes, instruction windows, call and branch targets, section-backed literals, three relative dispatch tables and four relocation records are retained. The records are selected evidence, not a whole-node coverage denominator.

### Hash-input context and outer writer

The existing `RE-009-app-hash-builder-94/closure-rows.tsv` associates low-lane row 22 with state offset `+0x3540` and closure `0x281b020`. Inside that already-studied closure, the call at `0x281b070` reaches `0x1eaa210`. The preceding setup at `0x281b055` stores serializer bytes `00 04 00 01`; the mode byte read at writer offset `+0xb` is consequently 1 on this path. The closure is context and is not one of the 18 newly selected function bodies. This links the following writer to a previously mapped app-hash input; it does not reproduce the hash, prove persistence, or establish runtime invocation.

`0x1eaa210..0x1eaa394` requests a three-entry map header when mode byte `+0xb` is nonzero and a three-element array header when zero. It writes names when the byte equals 1. The rows below apply to mode values 0 and 1; other byte values are not modelled.

| Order | Name | In-memory input | Value handoff |
| --- | --- | --- | --- |
| 1 | `tracker` | base | `0x2326d20` |
| 2 | `quorum_app_hashes` | base `+0x30` | `0x1e31c90` |
| 3 | `highest_quorum_height` | qword at `+0x48` | integer helper `0x25ac0d0` |

In named mode each field name is emitted before its value. Header, name and child failures leave through result-copy exits; the recorded conditional targets distinguish those stages. `fields.tsv` gives the literal addresses and `evidence.json` includes the addressing instruction that supplies each reported input displacement.

### Nested tracker and quorum rows

`0x2326d20` requests a three-field map or array, in order `name`, `hsc`, `i`. It passes the `name` pointer at input `+0x08` and length at `+0x10` to a string helper. For `hsc` it clears the length argument and calls the sequence-header helper at `0x2326dfa`; this path does not read a value from the input for that call. It advances the input by `0x18` for `i` and calls `0x25ddba0`, which collects entries then hands them to `0x1e4b530`. This observation is a selected serialization path, not a claim that all readers reject nonempty `hsc` values or that the nested map's key/value encoding is known.

`0x1e31c90` reads the quorum collection's pointer and count at its input `+0x08` and `+0x10`, emits a sequence header, steps by `0x40` bytes, and calls `0x1dd1f90` for each selected row. One row path requests an array header of two, passes the qword at row base to a child, and calls `0x1ea9da0` with row base `+0x08`. The alternate buffer path contains a direct `0x92` write. Child failures leave before subsequent stages. These offsets and the `0x40` stride describe memory, not an on-disk fixed record size.

The quorum value writer `0x1ea9da0` requests two fields and emits `app_hash` followed by `hot_user_to_signature` in named mode. The first child passes 32 input bytes and a 66-byte destination to an indirect formatter through relocation slot `0x5773120`; the second uses input `+0x20`, calls `0x25de780`, and passes the collected entries to sequence writer `0x1e2af60`. The latter walks collected entries at a 16-byte memory stride. `0x1ddc5b0` handles each collected signature entry: on the selected path it requests a two-element sequence, passes the key to the shared helper `0x1e0d0a0`, then calls `0x1e10640` for the value. That adapter reaches `0x1eac430`, a three-field writer:

| Order | Signature field | In-memory input | Handoff |
| --- | --- | --- | --- |
| 1 | `r` | base | `0x219b770` |
| 2 | `s` | `+0x20` | `0x219b770` |
| 3 | `v` | byte at `+0x40` | integer helper `0x25ac0d0` |

The `r` and `s` child helper is already covered by `bridge-validator-action-wire-94` and is a boundary here. Header, name, key and value failures have distinct recorded routes. The exact formatter output, the complete signature-key representation and collection order remain unproved.

### Reader dispatch and failure decisions

At `0x17ea910`, the relocation-backed descriptor referenced at `0x17eb217` says `struct AppHashVoteTracker with 3 elements`. Its classifier `0x16d1b50` checks every byte of `tracker` (7), `quorum_app_hashes` (17) and `highest_quorum_height` (21), returning selectors 0, 1 and 2; other names select 3. `key-comparisons.tsv` records all 45 byte compares and the failure destinations. The relative table at `0x2e2afc` selects the three field routes or an unknown-value helper. The key adapter has additional input paths, so this byte predicate does not prove that every possible key representation is accepted.

| Input on the selected outer reader path | Observed route after preceding children succeed |
| --- | --- |
| Known map field absent | Missing-field diagnostic naming the field. |
| Known map field repeated | Duplicate-field diagnostic naming the field. |
| Unknown map key | Calls `0x19682d0`; that helper's behavior is outside this packet. |
| Sequence length 0 | Length error before the first child. |
| Sequence length 1 | First child then length error before the second. |
| Sequence length 2 | First two children then length error before the third. |
| Sequence length 3 | Three children followed by the normal result route. |
| Sequence length greater than 3 | After three successful children, extra-element error route. |

The nested tracker reader `0x16a9410` has a first three-way relative dispatch and, after an `i` value, a second table at `0x289714` whose third route constructs a duplicate-`i` diagnostic. It separately checks duplicate `name` and `hsc` and calls a helper on an unknown selector. Its key adapter `0x16f9d10` is a shared boundary previously covered in `RE-009-vote-tracker-state-94`; its body is not analysed here. The complete nested-map acceptance and defaults remain unresolved.

The outer sequence's second child reaches `0x1a3ec40`, then the selected sequence visitor `0x24d94f0` and row reader `0x1978910`. On the fixed-array row route, a zero-length row fails before its first child, a one-element row fails after that child, and after both children the comparison at `0x1979028` requires exactly two. The second child is `0x188d500`, whose relocation-backed descriptor says `struct QuorumAppHash with 2 elements`. This reader contains separate missing-field and duplicate-field diagnostic routes for `app_hash` and `hot_user_to_signature`. These routes are conditional on successful earlier parsing; the table is not a universal error-precedence rule.

### Quorum-row reader initial reservation

In `0x24d94f0`, the input count is a 32-bit word. The comparison and conditional move at `0x24d9509..0x24d9517` select `min(count, 0x4000)` slots; the shift at `0x24d9525` multiplies that number by 64. For count 16,385 the initial reservation is still 16,384 slots, or 1,048,576 bytes. The loop calls row reader `0x1978910`, decrements the original count, and calls the separately relocated growth slot `0x57744c8` when the vector is full. Allocation failure and row failure have distinct exits and cleanup. **16,384 is an initial allocation cap, not a proved input-count rejection threshold.** `reservation-cases.tsv` is a static arithmetic model based on the recorded immediates, not execution of the node.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No compiled comparison, target execution, complete snapshot fixture, masking, whole-ELF match, or helper/vtable/data closure is claimed. The 13 focused unittest methods check the target digest, selected FDE fingerprints, field references and offsets, reader/writer edges, two dispatch tables, diagnostic routes, descriptor relocations and reservation boundaries. Negative controls alter a selected code byte, classifier byte and branch, a literal, two jump tables and a relocation; they also exercise a non-call opcode, unmapped addresses, a `.bss` read, invalid counts, and 11,475 single-byte changes across the three outer names. Tests are static controls rather than native behavior measurements.

## Results and limitations

The extractor records 18 selected FDE ranges, 60 direct-call sites, 67 conditional branches, 47 byte windows, 11 field references, 45 classifier comparisons, three relative dispatch tables, two indirect-call relocations and two type descriptors. These are selected records, not coverage of the complete component. The writer path, required outer fields, row arity, nested field order, selected failures and initial allocation arithmetic now constrain a reconstruction. Full nested `i` values and signature-map key encoding, empty-`hsc` compatibility on input, formatting and numeric encoding, ordering, complete malformed-input behavior, runtime reachability, actual checkpoint bytes and cross-release compatibility remain unknown. No full-scope progress gate is requested.

Next question: recover the nonempty `i` entries and signature-map entry readers without overlapping existing vote-tracker work, then compare complete synthetic fixtures in a separately authorized offline harness.
