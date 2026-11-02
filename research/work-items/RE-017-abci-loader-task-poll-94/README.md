# RE-017: trace the node 94 loader future through task creation and completion

Node #94's previously Location-linked loader future is reached through two task-table lanes that share the same initial state transition and completion layout, allowing a reconstruction to preserve the task object, conditional dispatch and cleanup decisions around that loader.

- Component ID: `abci`, task RE-017.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository base `e5c9b6436876b2a4a39daef813171f9879317699`; the unlicensed reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` was a lead only and supplied no implementation.
- Claim status: observations of selected bytes, relative transfers, relocation records, FDE extents and LSDA call-site records; conditional control-flow inferences are identified below. Runtime scheduling, type names and state-root semantics remain unresolved.
- Scope included and excluded: three new entry ranges, two task-construction and scheduler lanes, their common future wrapper, selected completion and cleanup paths, and their recorded exception call sites. The prior `state.rs` future and loader bodies, their existing call sites and GOT slots, the previously inventoried result-boundary body, other action/block paths, node #115 and visor are excluded.

## Reproduce

From the repository root with Python 3.12.3 and its standard library on Linux x86-64:

```sh
python3 tools/abci_loader_task_poll94.py --out work/re017-task-poll
python3 -m unittest tests.test_abci_loader_task_poll94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-017-abci-loader-task-poll-94 work/re017-task-poll
(cd research/work-items/RE-017-abci-loader-task-poll-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_loader_task_poll94.py --out work/re017-task-poll-a
PYTHONHASHSEED=31337 TZ=Pacific/Honolulu python3 tools/abci_loader_task_poll94.py --out work/re017-task-poll-b
diff -r work/re017-task-poll-a work/re017-task-poll-b
```

The generator authenticates the complete input before parsing and imports the repository's shared ELF, FDE and ULEB readers. It uses only file-backed sections and rejects ambiguous VA mappings; a NOBITS section is excluded even when its VA overlaps a file-backed section. It checks fixed instruction byte patterns, decodes only selected relative instruction forms, reads signed table entries and RELATIVE relocations, and checks selected LSDA headers and call-site tables. No disassembler or other external program is invoked by the generator or tests; the binary is never executed. GNU objdump 2.42 was used only for human inspection while choosing fixed windows. All generated files and their hashes are listed in the manifest; no operand masks or runtime fixtures are used.

## Evidence

Coordinates are linked ELF virtual addresses (VA), not runtime rebased addresses. Every generated record also carries a file offset where applicable. The actual `.eh_frame` FDE range and matching `.eh_frame_hdr` entry are checked for each selected range. FDE ranges are unwind ranges, not a complete source-function census. The listed observations cover the fixed windows and tables, not a complete instruction decode.

### Prior boundary and three entry contexts

The earlier [RE-017 state link](../RE-017-abci-state-link-94/README.md), [RE-019 loader](../RE-019-rmp-json-loader-94/README.md), and [ABCI state inventory](../abci-state-inventory-94/README.md) already identify the `state.rs` Location-bearing future at `0x22ae8a0` and its loader connection. This packet does not re-own their code or GOT records. The new direct call from `0x2013c94` targets `0x22ae8a0`; the prior inventory supplies the independently established `state.rs` connection.

| New entry FDE | Initialization and call | Location passed to spawn |
| --- | --- | --- |
| `0x22b8920` | `0x22b899f` writes zero at stack offset `0x22e`; `0x22b89ae` supplies stack offset `0x18`; `0x22b89b3` calls `0x229ec10`. | `0x56a0568`, `src/hl_node.rs:5:5` |
| `0x2032480` | `0x2032514` writes zero at `0x226`; `0x2032523` supplies `0x10`; `0x2032528` calls `0x229ec10`. | `0x5696f60`, `src/hl_node.rs:5:5` |
| `0x247bbf0` | `0x247bd53` writes zero at `0x286`; `0x247bd5b` supplies `0x70`; `0x247bd67` calls `0x229ec10`. | `0x56b7e88`, `src/hl_node.rs:5:5` |

Each difference is `0x216` relative to the passed input. The prior inventory records that same input offset in the already-owned future; this is a data-flow connection, not proof of an original source function name. A byte-pattern pass over `.text`, `.init`, `.fini` and `.plt` found these three `e8` candidates for `0x229ec10` and two for `0x2013c00`. All five selected sites also occur at the separately fixed instruction windows. The scan tries every byte and covers only this direct-call form; it is not a complete caller census.

### Creation, two callback tables and initial admission

`0x229ec10` copies `0x6368` input bytes, requests a heap allocation of the same size and copies the input to it. The allocation-null branch reaches an indirect failure call and a following `ud2` if that call returns. A thread-local status value of 2 takes a drop/free and diagnostic path; a separate mode word equal to 2 also drops and frees the input before a diagnostic. For the remaining selected mode values, its low bit chooses a lane:

| Condition on mode word | Construction | Table pointer stored in task `+0x10` | Table entry at `+0` | Table entry at `+0x18` |
| --- | --- | --- | --- | --- |
| Low bit 1 | `0x23c3c70` -> `0x200b3a0` | `0x56954a0` | `0x22a3d20` -> `0x1d7c8f0` | `0x229f990` -> `0x1d589c0` |
| Low bit 0, after the separate equality test | `0x2888350` -> `0x2003d20` | `0x5693650` | `0x22a4460` -> `0x1d8e930` | `0x229f710` -> `0x1d589c0` |

The four table slots have `R_X86_64_RELATIVE` records with symbol index zero and the stated thunk addends. These table relationships are static: a runtime dispatcher must select a given slot for that edge to run. Both constructors request `0x80` bytes and copy the task record. The recorded fields are task `+0x20` for the context, `+0x30` for a four-byte variant initialized to zero, and `+0x38` for the copied future pointer. Both construction lanes pass the immediate state word `0xcc` to the constructor, which places it at task offset zero.

The two admission windows test bit 2, the low two bits and a `0x3f` bound, then use `lock cmpxchg` with a retry on failure. For the actual initial word `0xcc`, **if the word remains unchanged and the comparison-exchange succeeds**, the derived replacement is `0xc9` and the selector is 0 in each admission table. The selected targets are `0x1d7c967` and `0x1d8e9a7`, respectively, and each calls the common wrapper. `initial-admission.tsv` records the two calculations; synthetic tests exercise the other bit and range branches. They do not execute the target or model concurrent writes.

The four entries of each scheduler table are retained in `tables.tsv`. For the first and second admission tables respectively, index 0 enters the wrapper call; index 1 reaches a variant-2 replacement path; index 2 returns; and index 3 reaches an external helper before returning. The post-call tables have distinct entries for return, an external callback sequence, a helper sequence and a variant-2 replacement. These are table-index observations; reachability of each index depends on the recorded bit tests and successful atomic operations.

### Future wrapper, completion and consumption

Both scheduler lanes call `0x2013c00` with the context at task `+0x20`. Its tested word at context `+0x10` is therefore task `+0x30`; the future pointer at context `+0x18` is task `+0x38`. A nonzero tested word selects an indirect diagnostic call. For zero, the wrapper calls the prior `state.rs` future at `0x2013c94`. When the returned low byte is zero, it calls `0x1fa3d10` on the variant and writes tag 2; the nonzero branch leaves that completion step unselected. This statement is conditional on the calls returning and does not assign Rust `Poll` names to the byte values.

The zero-return scheduler branches at `0x1d7cb03` and `0x1d8eb27` construct a 32-byte input record with a four-byte tag 1, zero words at offsets `+8` and `+16`, and the then-current `rdx` at `+24`. `0x201c250` first calls the variant dropper on task `+0x30`, then copies the two 16-byte chunks into that location. The origin or semantic meaning of the saved `rdx` is not established; the wrapper and cleanup calls can affect caller-saved registers.

Each table's `+0x18` relocation leads through its thunk to `0x1d589c0`. After an indirect boundary returns a nonzero low byte, that function snapshots task `+0x30..+0x4f`, stores tag 2 at `+0x30`, and checks that the snapshotted tag is 1. A different tag reaches an indirect diagnostic call and a following `ud2` if the call returns. For tag 1 it re-reads the three words at task `+0x38`, `+0x40` and `+0x48`, conditionally cleans the destination's old value, and writes destination tag 0 and those words. If the initial boundary returns zero, it returns without that copy. Since the payload is re-read after the tag snapshot and mutation, equality to the earlier snapshot requires a stability assumption; the boundary's synchronization semantics are not recovered.

The new entry ranges call the previously inventoried boundary `0x2046b70` and inspect its output. In `0x22b8920`, a nonzero output tag selects state byte 3 and returns that tag; a zero tag selects a payload check, with a nonzero first payload word reaching a 43-byte `Result::unwrap` diagnostic and fallthrough `ud2`. The alternate entry has the same diagnostic bytes and its own Location at `src/hl_node.rs:5:39`. The inventory names `0x2046b70` as a boundary, but this packet does not decode that existing FDE or claim that it selects table `+0x18`; thus the final reader-to-entry connection remains conditional rather than a proven runtime handoff.

### Drop and failure paths

`0x1fa3d10` dispatches on its four-byte tag. Tag 0 calls `0x1fc6250` on the pointer at `+8` and, if that call returns, passes that pointer and size `0x6368` to an indirect release slot. Tag 1 has separate zero checks for its fields, an optional callback and a size-dependent release; other tags return through the selected branch. The unspawned-input path calls `0x22569c0` before its release, and `0x2244480` provides another selected drop-then-release sequence.

Both `0x1fc6250` and `0x22569c0` subtract 3 from the zero-extended byte at future `+0x216` and use an unsigned bound of 10 before their 11-entry tables. Consequently input byte values 3 through 13 select entries and all other byte values take the outside-table branch. The corresponding table destinations have the same offsets within the two FDE ranges for all 11 entries. Their helper call targets differ; this does not claim whole-body or helper equivalence. The two independent constructor allocation-failure branches have LSDA entries naming cleanup pads that call `0x1faa630` and `0x1fa9d50`, whose selected paths call the same variant dropper.

`lsda-headers.tsv` and `lsda.tsv` retain the selected header and call-site bytes and decoded ranges; `lsda-calls.tsv` associates each selected call's return PC minus one with at most one row. For example, the future call at `0x2013c94` has landing `0x2013d6c`; the old-variant drop at `0x201c2bc` has landing `0x201c31d`; and the future drop at `0x1fa3d7d` has landing `0x1fa3dc0`. If the second landing is selected, its pinned code copies the new 32-byte record before a cleanup call and a call to `0x5660110`, assuming the cleanup call returns. The action/type tables, personality choices and actual exceptional execution are not decoded; a recorded pad alone does not prove an unwind occurs.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. There is no compiled object, compiler or linker pin, raw-equal or normalized comparison, fixture execution, helper closure, vtable identity proof or target execution. Normalization masks are empty. This packet supplies static constraints for a later independently authored implementation, including the conditional state-word calculation and the object offsets above.

## Results and limitations

`summary.json` derives 23 selected FDE ranges, 89 fixed windows, 196 selected relative transfers, branches and RIP-relative LEAs, 38 jump-table entries, 19 layout operands, 4 callback relocations, 5 Location records, 2 literals, and 2 initial-admission calculations. It also records 19 LSDA headers, 167 call-site rows and 79 selected call lookups, 47 with nonzero landing addresses. These are selected-record denominators, not function coverage or completion percentages.

The focused suite passes 31 tests with no skips, including corrupted input digest, instruction opcode and displacement, real FDE extent, both table guards, wrong in-range and out-of-range table targets, relocation type/addend/duplication, Location pointer and bytes, literal length/bytes, LSDA row and pointer, NOBITS/ambiguous mapping, all 256 drop-tag bytes, and state-word boundary cases. An independent test uses the shared ELF reader to rederive 19 direct edges, all 4 selected callback relocations and both 11-entry offset lists without the producer mapping or decoder. Two generations with distinct hash seeds and time zones compare byte for byte with binutils absent from `PATH`; artifact verification and catalogue checking pass. The full repository suite was not run under the stated memory constraint.

The complete begin/action/end-block path, state mutation and state-root inputs are not mapped here; the ABCI gate remains 0/4 and no gate is requested. FDE extents, selected byte patterns and the `e8` scan cannot establish complete CFG or dynamic-call coverage. The existing loader, result-boundary body, allocator, scheduling, callback and release helpers remain outside ownership, as do action/type-table interpretation and all live behavior. Next question: establish the existing result boundary's selected table slot and the stability/identity of the task payload, then connect that bounded result to state mutation without re-owning earlier work.
