# RE-010: schedule-cancel admission, expiry and counter reset in node #115

The selected node #115 path gates both scheduling and clearing on an aggregate quantity, compares a requested deadline strictly after a five-second cutoff, and connects the stored per-key counter to expiry and date-triggered reset.

- Component ID: `action-dispatch` (RE-010; the expiry handoff also touches `exchange`).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical RE-014 at `ed15cdefc503ba2d845939fe7b65bd58b6202c59` supplies dispatch context, and reference `999556f6e0a474b8312db96ec3149e1c44e97c23` supplies labels only. No reference code is copied.
- Claim status: selected byte, FDE, relocation and control-transfer facts are observations; path labels, data meanings and normal-return predicates are inferences. The serializer-to-execute name join remains inferred. Synthetic vectors are not captured execution.
- Scope included and excluded: a selected case's core, its aggregate, time and map paths, and the connected timed scan through its per-key handoff and reset. This does not survey every branch of the large expiry function, prove the full action deserializer, close all helpers, reconstruct a Rust component, or assert binary equivalence.

## Reproduce

Run from the repository root on Linux x86-64, with Python 3.12.3 and the repository's shared `tools/elf_index.py` and `tools/fde_extents.py`. The binary is input data only and is authenticated before evidence is emitted. The generator uses the Python standard library and shared parsers, calls no external program, and excludes SHT_NOBITS sections from file-backed VA translation. The two output directories below must be distinct and empty; replace placeholders with relative writable directory names.

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/re010_schedule_cancel_115.py --out <first-dir>
PYTHONHASHSEED=93657 TZ=Pacific/Honolulu python3 tools/re010_schedule_cancel_115.py --out <second-dir>
diff -r <first-dir> <second-dir>
python3 -m unittest tests.test_re010_schedule_cancel_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-010-schedule-cancel-core-115 && sha256sum -c MANIFEST.sha256)
```

Compare the 20 generated files with the same-named files beside this README; `README.md` and `MANIFEST.sha256` are not generator outputs. `MANIFEST.sha256` gives the recorded output hashes. The generator never runs the node or uses network access; it writes only the requested evidence directory.

## Evidence

All code addresses below are linked ELF virtual addresses. File offsets in the generated tables are zero based. `functions.tsv` joins the #115 `.eh_frame_hdr` starts to the actual FDE records and pins each selected half-open extent and SHA-256 of its executable body. A matching FDE is a recorded unwind range, not proof of a Rust source-function name or all possible entrypoints. Instruction boundaries below were selected by static inspection and checked against fixed patterns and body hashes; the generator is not a general disassembler, and the branch list is selected rather than a complete CFG. It retains full body bytes for all 23 selected FDEs. Raw selected branch operands, relocations, constants, call targets and windows are in the corresponding TSVs.

### Relation to dispatch and the reference split

The historical #115 RE-014 packet binds serializer index 18 to the stored name `scheduleCancel`, and reports the corresponding execute-arm name as inference I2, not a proven deserializer handoff. As a contextual cross-check, `dispatch-context.tsv` re-reads the shared bias and index idiom, three selected jump-table entries, the serializer name relocation and store, and the two execute-arm call operands from #115 bytes. Index 18 with bias `0x86` gives tag `0x98`; the serializer arm stores the name `scheduleCancel`, while the execute arms reach `0x283c900` and `0x2c06530`. This rechecks prior work and does not claim those arms or wrappers as new discoveries. Separately extracted rel32 call bytes at `0x283c94f` and `0x2c067f9` both resolve to the newly studied #115 core FDE `0x2c2cb40..0x2c2cf4a` (`calls.tsv`, `functions.tsv`). The association of that execute tag with the serialized name remains conditional on I2. The name remains a path-role inference and does not prove the full input decoder.

The reference file `l1/exchange/handlers/18_schedule_cancel.rs` is an agent-created naming and layout lead, not evidence for an original compiler function boundary. Here the dispatcher's earlier first-call FDE and the core's independently observed FDE are separate ranges. A named reference file cannot establish a one-to-one source split, ABI, or ownership of the expiry function.

Historical node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, had a reported case-18 arm at `0x2759d57`, wrapper `0x1e5fc40`, and gate `0x2721260` (historical `fees-schedule-cancel-gate-94`). These are #94 linked VAs, used only as leads. The current packet re-reads #115 FDEs, call operands, constants, layouts, and status words from the #115 image; it does not claim cross-release function or behavior equivalence or revalidate the unavailable #94 image.

### Selected function map

Roles are descriptive inferences; exact extents, FDE coordinates and hashes are in `functions.tsv`.

| #115 FDE start | Selected role and observed connection |
| --- | --- |
| `0x2c2cb40` | Request core; calls aggregate, time conversion and map-entry helpers. |
| `0x2a8ae60`, `0x4716be0`, `0x4716cc0` | Two-lane aggregate and DEX/base record lookups. |
| `0x44e9f40`, `0x3d25c00` | Two lazy-default constructors; their initial selected field pairs are zero. |
| `0x44dd1b0`, `0x44db370`, `0x3ced300`, `0x3c4c590` | Four callback variants copy the selected initialized field pairs into the lazy cells. |
| `0x1628f50`, `0x162a9a0`, `0x1567a50` | Ordinal conversion, seconds adjustment and the error-producing helper. |
| `0x2db4460`, `0x2422570`, `0x24cb7e0`, `0x24bb380` | Map entry, value materialization, compact search and compact insertion. |
| `0x2bdf270`, `0x2bdf8f0`, `0x262eef0` | Clock update, conditionally invoked expiry driver and keyed-map iterator. |
| `0x2bf9910`, `0x2dceaf0`, `0x24c0ee0` | Per-key handoff, date-triggered reset and compact reset. |

The lazy cells at `0x64fda80` and `0x64fd958`, their vtable slots and six RELATIVE relocations are retained in `lazy-defaults.tsv` and `lazy-relocations.tsv`. Under normal completion of initialization, and provided the defaults have not later changed, a missing selected record supplies zero for both aggregated fields. The generic once helper and allocation/overflow helpers are outside this packet.

### Admission decision and state

The core copies a 20-byte key, calls `0x2a8ae60`, and checks the first returned u64 against `100000000` at `0x2c2cb7e`. The aggregate visits the vector at state `+0x7c8/+0x7d0` with stride `0x510`, and a base lookup at state `+0x3f0`. It accumulates the two fields at DEX record `+0x50/+0x58` and base record `+0x40/+0x48`; a carry calls an overflow hook and, if that hook returns, the corresponding sum saturates. The error payload divides the first sum by `100.0`. The aggregate's overflow hooks reference #115 Location records for `l1/src/scaled_vlm.rs` and `l1/src/raw_vlm.rs`, extracted with their relocations in `source-locations.tsv`. These locations support interpreting the lanes as scaled and raw volume, but do not by themselves establish units or source-level types.

The following table describes the selected normal-return order, not all allocator, hook or unwind outcomes. A later row is reachable only after the earlier conditions pass. Status values are internal words, not established wire codes.

| Priority | Predicate / selected branch | Observed normal-return outcome |
| --- | --- | --- |
| 1 | first sum `< 100000000` | `0x11d`, floating payload; no core map operation. This check also precedes clearing. |
| 2 | low bit of option word is zero | Search the map at state `+0x3fa8`; clear value date at `+8` only if found, without inserting; `0x1a2`. |
| 3 | option present, fast time input exceeds `0x292f57ce8accbff` or ordinal conversion returns zero | Enter `0x1567a50`; on normal return it marks an error and the core returns `0x89`. The fast bound alone is not a maximum valid calendar date. |
| 4 | converted deadline is not strictly later than current state time plus 5 seconds | `0x11b`. Comparison is signed date then unsigned seconds and nanoseconds. |
| 5 | later deadline, materialized value's first u64 `> 9` | `0x11c`. Entry materialization and representation changes may already have occurred. |
| 6 | later deadline, first u64 `<= 9` | Store the date dword at value `+8`, seconds/nanoseconds together at `+0xc`, and return `0x1a2`. The core does not increment the first u64. |

The five-second helper call passes `edx=5`, `ecx=0` at `0x2c2cc6d..0x2c2cc77`. Equal cutoff is rejected. For millisecond-aligned times with successful conversion and ordinary cutoff calculation, `+5000 ms` is rejected and `+5001 ms` passes this particular comparison. A cutoff-computation failure branch instead uses the three recorded fallback fields `(0x7fffd6de, 86399, 999999999)`; it must not be silently treated as ordinary addition. The selected fast unsigned arithmetic is independently checked against integer division on 264 synthetic inputs. The separate ordinal helper's final year guard accepts `-262143..262142` at that guard; this is not a proof of the complete calendar conversion.

The map has a 20-byte comparison key and 48-byte compact records. The representation marker is `0x8000000000000000`. On the selected entry path a tree with size below 32 is converted to compact form; a compact miss at size at least 64 takes the tree-conversion path. The value has a first u64 followed by three dwords. Exact write instructions are in `state-writes.tsv`; search/insert and allocation callees are not all closed.

### Clock, expiry and daily counter

The FDE at `0x2bdf270` compares an incoming three-dword time with state `+0x60/+0x64/+0x68`; when it is strictly later, it first copies the previous triple to `+0x6c/+0x70/+0x74` and installs the input triple. Its call at `0x2bdf499` passes a context containing that same state pointer to `0x2bdf8f0`; the driver dereferences it at `0x2bdf916`. The call is conditional on a preceding comparison, so this is not a claim that every clock update invokes a scan.

On the selected normal-return scan, the driver reads the current triple, iterates the same map via `0x262eef0`, ignores entries whose date is zero, and selects entries whose stored triple is less than or equal to the current triple. For every selected key it appends the 20-byte key to a vector, increments the first u64 with saturation at `u64::MAX`, and clears the date dword. After the scan it calls `0x2bf9910` for each collected key with selector 2 and flag 15. That function visits DEX entries and makes the recorded per-DEX calls `0x22f2000` and `0x2419810`, then the base calls `0x22f2160` and `0x241a3c0`. Their semantics and successful order cancellation are not established by this packet.

After the handoff, the driver compares the signed date at state `+0x6c` with state `+0x60`. Only the less-than branch calls `0x2dceaf0` on the same map. Its selected tree path zeroes the first u64 and invokes deletion for date-zero values; `0x24c0ee0` zeroes compact counters and removes date-zero records through compaction. This expiry increment and date-dependent reset support interpreting the first u64 as a count of triggered scheduled cancels for a day. It does not prove behavior if intervening calls fail, unwind, or receive malformed state.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph and build flags: **not yet implemented**. Two-build comparison, normalization masks, helper/data closure and whole-ELF equivalence: **not yet measured**. No target process, chain, private state, or external service was accessed. The synthetic predicate and arithmetic tables document expected selected normal-return decisions; they are not traces or an independent Rust-to-binary comparison.

## Results and limitations

The deterministic extraction covers 23 explicitly selected FDEs, 144 selected branches, 28 selected direct calls (including two contextual incoming edges), 15 selected RIP-slot calls, 2 selected register-indirect calls, 63 instruction windows, 3 contextual dispatch rows, 3 request-state writes, 5 expiry/reset write windows, 2 lazy defaults, 6 lazy relocations and 3 source Location records. These are the selected denominators, not a count of all node functions or a matched-window denominator. The output also contains 360 synthetic admission vectors, 96 synthetic expiry vectors, 24 time-order vectors, 264 time-arithmetic vectors, 16 saturating-add vectors and 9 ordinal-year-guard vectors.

Focused validation: 41 tests pass with a binutils-free PATH and no skips, including wrong digest, corrupted body/FDE/branch operand/relocation/table, non-file-backed or ambiguous address, threshold, equality and overflow controls. Two generations under different hash seeds and time zones match byte for byte. Artifact verification and catalogue check pass. These tests establish the extractor's checks and selected model consistency, not actual execution of the node. No component progress gate is requested; the full action-dispatch component remains incomplete.

Next question: trace the input deserializer's actual tag handoff to both previously mapped execute families, and close the downstream per-DEX/base cancellation callees and their error behavior before treating the entire transaction path as reconstructed.
