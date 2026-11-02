# RE-021: BLAKE2b registry value and container cleanup

This packet establishes how the address-09 registry value and its containing map are cleaned up, including reference-counted and virtual values, so an independent reconstruction can distinguish a tag-zero callback from dynamically owned entries on both ordinary and exceptional paths.

- Component ID: `evm`; RE-021 continues the existing BLAKE2b work item and is not a new row in the official task queue.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference was a lead only; no reference implementation is copied.
- Claim status: observations for authenticated bytes, decoded FDE extents, relocation records, selected transfers and exception call-site records; inferences for container roles, ownership names and path composition; unresolved for live reachability, concrete runtime pointers and complete exception actions.
- Scope included and excluded: the map/set aggregate cleanup, map entry and backing-storage cleanup, partially initialized map and source-array cleanup, iterator/vector cleanup, per-value drop branches, last-primary and secondary-counter cleanup, and their selected unwind landings. The existing address-09 object, registry constructor, lookup and compression bodies are dependencies and are not selected as new functions. Node #115, visor, target execution and complete HyperEVM recovery are excluded.

## Reproduce

From the repository root with the authenticated artifact present, using Python 3.12.3:

```sh
python3 tools/artifacts.py verify
python3 tools/re21_registry_drop94.py --out research/work-items/RE-021-blake2b-registry-drop-94
python3 -m unittest tests.test_re21_registry_drop94
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-blake2b-registry-drop-94 && sha256sum -c MANIFEST.sha256)
```

For independent output directories, replace the placeholders with two empty directories:

```sh
RE21_PYTHON=$(command -v python3)
PATH= PYTHONHASHSEED=1 TZ=UTC "$RE21_PYTHON" tools/re21_registry_drop94.py --out <tmp-dir-a>
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$RE21_PYTHON" tools/re21_registry_drop94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
PATH= "$RE21_PYTHON" -m unittest tests.test_re21_registry_drop94
```

The exporter creates 19 evidence files. This README and MANIFEST are maintained separately. It authenticates the complete input before parsing, imports the repository's `elf_index` and `fde_extents` readers, rejects SHT_NOBITS as file bytes, and runs no external program. GNU objdump 2.42 was used only for manual inspection; neither generated evidence nor tests invoke it or parse its output. No captured instructions are executed, including under emulation.

## Evidence

Addresses are linked ELF virtual addresses before load bias; generated tables retain file offsets. A selected FDE is an unwind-described extent, not by itself a complete function boundary or a component-coverage denominator. `functions.tsv` joins each selected FDE to the unwind index and records its CIE, LSDA pointer, length and raw-body digest. `bodies.json` retains the selected body and FDE/CIE bytes. The bounded instruction-shape walker records `instructions.tsv` and syntactic `transfers.tsv`; it is not a general-purpose disassembler or proof of complete reachability. Branches within each FDE and LSDA landing/range ends are checked against its instruction boundaries. Below, "free" and "release allocation" describe inferred roles for calls to an unresolved free-shaped helper; they do not assert its unexamined implementation.

The earlier BLAKE2b packet binds address 09 to a tag-zero callable. Pending PR #1373 traces the record through registry construction and lookup; that packet owns those functions. Here `address-anchor.json` independently reads the tag and 20-byte key at the original data record, while `prior-boundary-calls.tsv` retains only eight short call patterns into the new selection. The earlier packet supplies their containing instruction boundaries; an isolated `e8` byte pattern alone would not establish them. Their enclosing earlier-owned functions are not in the function count. In particular, the earlier constructor's publication-loser call at `0x4e99997` targets the newly examined map cleanup, and its exceptional cleanup calls also target selected iterator and aggregate cleanup functions. The interpretation of the constructor's publication branch remains a dependency on the earlier packet.

### Selected cleanup functions

| FDE start | Bytes | Inferred role in this path |
| --- | ---: | --- |
| `0x4e94d80` | 250 | Clean partially initialized map entries after a clone failure. |
| `0x4e952d0` | 59 | Release the address-set backing allocation. |
| `0x4e95310` | 425 | Visit occupied map entries, release applicable values, then release map storage on normal return. |
| `0x4e98b60` | 109 | Clean the map/set aggregate; release the set if the map cleanup unwinds. |
| `0x4e98bd0` | 94 | Clean initialized vector elements and their allocation. |
| `0x4e9bb90` | 171 | Clean one tagged value at an insertion-failure boundary. |
| `0x4e9cd50` | 171 | Clean one remaining iterator value during unwind. |
| `0x4e9d0d0` | 368 | Clean remaining iterator records and backing storage. |
| `0x4e9d6c0` | 171 | Clean one remaining vector value during unwind. |
| `0x4e9d810` | 260 | Clean the initialized vector's value elements. |
| `0x4e9e410` | 81 | Release the secondary count and possibly its allocation on an unwind path. |
| `0x4e9e470` | 152 | On last-primary release, run an optional payload callback and release the secondary count. |
| `0x4e9e550` | 260 | Clean a selected initialized range of source records. |
| `0x4e9fb80` | 171 | Clean one remaining source record during unwind. |

`semantic-windows.tsv` preserves the original bytes for the reviewed path, `byte-predicates.tsv` checks fixed opcode patterns, `operands.tsv` decodes selected offsets, immediates and two LEA multipliers from those checked bytes, and `decisions.tsv` records branch bytes, calculated destinations and explicitly interpreted outcomes. The 49 decision rows are a selected semantic ledger, not a claim that the whole node has 49 branches.

### Value tags and last-reference handling

The first two fields of each source value are a tag word and payload word; its third word is available to dynamic variants. The prior packet establishes that the map rearranges a source record into a 20-byte key and a 24-byte value in a 48-byte bucket. The map cleanup reads the tag at the value position, scans 16 control bytes at a time, and counts only occupied entries. For an ordinary control pointer `C` and bucket index `i`, the tag read corresponds to `C - 48*(i+1) + 24`. This relationship is conditional on the earlier packet's bucket-layout interpretation and on a valid map header.

| Canonical value tag | Observed cleanup decision |
| ---: | --- |
| 0 or 1 | Return or advance without a per-value callback, reference decrement or payload free. |
| 2 | Atomically decrement the word at the payload pointer; a nonzero result continues, while zero calls the last-primary helper through slot `0x57733e0`. |
| 3 | Load a callback from the descriptor at payload word 2, call it if non-null, then pass the payload to the free boundary only if descriptor size is nonzero. |

The actual instruction sequence first performs an unsigned **64-bit** comparison with 2, then a **32-bit** equality comparison with 2. Thus the labels above are limited to canonical tags; high-bit synthetic tags are useful corruption controls but are not claimed to occur in the target. The presence of tag-2 or tag-3 values in this particular standard registry is not established. A zero counter would wrap under the observed decrement rather than take the zero-result branch; valid counter initialization and ownership are assumptions, not established runtime observations.

`address-anchor.json` shows that the previously identified address-09 source record has tag 0. If that value is present in the map and the occupied-entry scan reaches it, this tag takes the no-per-value-cleanup arm; the map's backing allocation is handled separately. It does not call the BLAKE2b function as a destructor. This does not prove that any live process selected that registry, that its key was not replaced, or that a callback was invoked.

The slot at `0x57733e0` has a symbol-free `R_X86_64_RELATIVE` addend `0x4e9e470`. In that selected helper, the descriptor supplies an optional callback at offset 0, a size word at offset 8 and an alignment word at offset 16. For a valid, positive power-of-two alignment `a`, its payload argument is at object+`max(16,a)`. The helper then checks a sentinel pointer, atomically decrements a second word at object+8, and, only on a zero result, computes the allocation length `align_up(size+16,max(8,a))` before conditionally reaching the free boundary. These formulas assume non-overflowing layout values; the target instructions do not establish that arbitrary inputs satisfy those assumptions. The names primary/secondary and descriptor are inferences from these byte uses. The actual dynamic callbacks and object layout invariants are not recovered.

### Storage and partially initialized records

On the normal map-cleanup path, for a valid nonempty mask `m`, the generated windows show a map allocation base of `control - 48*(m+1)` and byte length `48*(m+1) + (m+1) + 16`. The set helper uses `control - align_up(20*(m+1),16)` and length `align_up(20*(m+1),16) + (m+1) + 16`. A zero mask returns before the corresponding free call. These expressions are the observed arithmetic for valid, non-overflowing layouts; the tests' invalid-layout rejection is a property of the synthetic model, not a target error contract. The common free-shaped slot `0x576e010` resolves by RELA to `0x54c8cb0`; allocator internals are not analyzed.

The iterator cleanup computes its remaining-record count from an end/current pointer difference using a multiply/shift division by 48 and visits records at stride 48. The vector cleanup uses its stored element count and the same stride. The source-range cleanup derives its count from the two supplied indices. Their normal paths and their distinct partially initialized paths are recorded separately; valid ranges and complete initialization are prerequisites, not facts recovered about live memory.

### Exceptional paths

`exceptions.json` retains all 39 call-site rows in the 12 selected LSDAs. `exception-calls.tsv` joins instruction-shaped calls to their covering rows, including rows with no landing; `exception-edges.tsv` isolates the 18 calls with a local landing. Action indices are retained as numbers: action-chain and type semantics are not decoded.

| Call or condition | Local landing | Selected effect before onward unwind |
| --- | --- | --- |
| Map virtual callback at `0x4e953f3` throws | `0x4e95484` | Free the current dynamic payload if its size is nonzero, then enter the unwind boundary. No later map-entry or backing cleanup is shown inside this landing. |
| Aggregate map cleanup call at `0x4e98b67` throws | `0x4e98bb6` | Call the selected set cleanup on aggregate+`0x28`, then enter the unwind boundary if that cleanup returns. |
| Last-primary payload callback at `0x4e9e498` throws | `0x4e9e4f2` | Call `0x4e9e410` to process the secondary count, then enter the unwind boundary if it returns. |
| Iterator value callback at `0x4e9d164` throws | `0x4e9d1d2` | Conditionally free the current payload, drop remaining records through `0x4e9cd50`, release iterator storage and continue unwinding, subject to normal cleanup returns. |
| A later iterator cleanup call at `0x4e9d20c` throws | `0x4e9d23a` | The LSDA records action 1 and the landing calls slot `0x576e128`; its implementation and full action semantics are outside this packet. |

The map's last-primary helper call at `0x4e953d1` lies in an LSDA row with no local landing. That is a statement about this FDE's encoded call-site row, not a claim that outer frames perform no cleanup. The target of direct calls at `0x5660110` is bound through its PLT bytes, relocation and dynamic symbol to `_Unwind_Resume` in `unwind-import.json`; actual dynamic-loader resolution is an external condition.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, compiler/linker flags, two-build comparison, target behavior and whole-ELF identity: **not yet implemented/measured**.

Four selected single-value cleanup bodies have different raw SHA-256 hashes but equal bytes after masking exactly four 4-byte PC-relative displacement fields per body. `comparison-masks.tsv` retains every original displacement, and the exporter first verifies that the three RIP-relative operands resolve to the same two slots and the direct call resolves to the same PLT entry. `cleanup-comparison.tsv` is a comparison among four captured target bodies; it is not a source-build or binary-equivalence result. No other operand is masked.

The focused tests use small, explicitly synthetic models for tag comparisons, counters, occupied-control scanning and valid storage geometry. They do not execute the target. Controls reject a wrong artifact digest, corrupt instruction bytes, unsupported and truncated instruction shapes, a branch into an instruction, invalid/NOBITS/cross-section/ambiguous addresses, bad FDE joins, duplicated or altered relocations and PLT imports, malformed LSDA, and corrupted masked displacements, including substitution of another otherwise valid slot. They also exercise tag-width, control-group, and count-zero boundaries. Model input validation is not evidence of target-side validation.

## Results and limitations

The extractor records 14 selected FDE extents containing 2,742 code bytes, 866 walked instruction shapes, 190 syntactic transfers, 54 fixed byte predicates, 35 operand projections, 24 semantic windows, 49 reviewed decisions, 12 LSDA tables with 39 rows, and 18 local exceptional call edges. The selected corpus is not a whole-component function denominator. The focused suite passed 64 tests with zero skips; the two independent regenerations and other repository checks are reported in the submission draft.

Helper closure remains open for allocator and arbitrary destructor internals. Call-target closure is partial: the two RELATIVE slots and unwind PLT import are bound, while vtable-selected callbacks and dynamic loader behavior remain external. Data closure is partial: the static tag/key are bound, but actual registry contents, object pointers and reference counts are not observed. No Rust build, behavioral comparison or whole-ELF comparison exists. The complete HyperEVM first task and all four `evm` gates remain open; no gate is advanced.

The supplied open/merged PR snapshots and local work-item evidence were screened for the selected FDE starts. The offline restriction prevented a fresh public main and PR refresh; the submitting account must repeat that check. Next question: establish the remaining unowned dynamic-value constructors and clone ownership under the same registry representation, then compare an independent Rust implementation with separately authorized target-grounded fixtures.
