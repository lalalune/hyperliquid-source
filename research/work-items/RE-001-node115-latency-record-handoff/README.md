# RE-001: node115 latency-record handoff and local state publication

Component: foundation / instrumentation. Question: how does the previously opaque `0x4e3d2c0` helper route the latency record, refresh its local subrecord and publish the accompanying tuple?

## New observations

The complete range `0x4e3d2c0..0x4e3d49d` contains 477 bytes / 114 LLVM instruction rows. Existing `RE-001-node115-latency-projection` establishes the caller at `0x51c9c63`, including the uncapped value at record-relative `+0x18`, but explicitly excludes this helper. This packet freshly qualifies its body; it does not repeat the upstream arithmetic or establish persistence.

1. Entry saves incoming RDX in R12 (the record pointer), RSI in R15 (a 12-byte tuple-like input), and RDI in R14 (object). It copies the input's qword and dword into stack `+0x10/+0x18`, then calls slot `0x64e0f80 -> 0x1546570` with output at stack `+0x60`, the object and that local copy. This call occurs before the following guard; it may have opaque effects.
2. `0x4e3d306` zeros EAX, compares 0 with the reloaded qword at object `+0x48`, and uses JNO after an intervening flag-preserving MOV. For raw two's-complement words, signed subtraction `0-x` overflows exactly when x is `0x8000000000000000`. Thus only that object-word pattern takes the non-JNO early route. That route skips local publication; provider output word at stack `+0x68` equal to the same sentinel or zero skips the cleanup-shaped call, otherwise it passes stack `+0x70`, that word and EDX=0 to slot `0x64df4a0`. This is not a global no-effect or ownership proof.
3. On the other route, RBX becomes object `+0x48`. A provider output word at stack `+0x68` equal to the sentinel skips the refresh block. Otherwise the body retains dword output `+0x60`, bytes `+0x64/+0x65`, and three qwords at `+0x68..+0x80`; slot `0x64e0020 -> 0x14c3b30` transforms the copied three-word input into the stack block at `+0x10`. After opaque helper `0x4e507b0`, the body copies five 16-byte chunks to object `+0x48..+0x98` (80 bytes), then publishes the retained dword at object `+0x98` and bytes at `+0xa8/+0xa9`. The exact load/store order, including the exceptional cleanup copy, remains in the full transcript. No Rust container or serialization layout is inferred.
4. It copies the current input tuple again, passes object `+0x48`, this local tuple and the original RDX record pointer to `0x50e6e50` at `0x4e3d3fc`. This is the concrete record handoff. The body then reloads the original RSI tuple and stores its qword at object `+0x9c` and dword at `+0xa4`. Those are observed post-call publications, conditional on ordinary ABI preservation and valid nonproblematic aliases; the downstream helper's use of the record/value remains unknown.
5. A nonzero object byte `+0xaa`, then a nonzero byte through slot `0x64e0f88 -> 0x64ffe50`, then a non-sentinel object subrecord enable the optional tail. The tail calls `0x14c3950`, `0x1533e80` and, for a nonzero result, `0x14c4d00`. The slot denotes a static relocation, not an observed runtime global value. No writer, flush, clock or durability effect is established.

The raw guard relation above follows from signed subtraction's mathematical range: positive x gives a representable negative result; negative nonminimum x gives a positive result at most `i64::MAX`; the signed minimum alone would require `+2^63`. This is an arithmetic explanation of one statically identified branch, not execution of instructions or an original source-type claim.

## Before, after and remaining question

Before: the latency projection packet stopped at this record helper boundary. After: the complete helper's local guards, publication offsets and original record-pointer forwarding are reproducible. Opaque provider/shaper/record/tail functions and the actual meaning of object/global fields remain open. The uncapped value is handed onward; it is still not proved stored, encoded or persisted. Next: recover `0x50e6e50`'s independently validated record consumption and outputs before naming a history format.

## Reproduce and verification boundary

Target: node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base: `05bc2de303c05525b71e7e257426e741bc66a390`. All coordinates are linked ELF VAs, ends exclusive; file offsets are derived from authenticated sections. FDEs are unwind-described ranges rather than a complete source-function census. No original source names or high-level types are recovered. New code/prose are independently authored under the project's MIT terms; captured bytes retain original rights. No unlicensed inferred source is used.

From repository root, with the pinned artifact materialized:

```sh
python3.11 -B research/work-items/RE-001-node115-latency-record-handoff/collect.py
python3.11 -B research/work-items/RE-001-node115-latency-record-handoff/collect.py --output work/RE-001-node115-latency-record-handoff-fresh
```

The output directory must be absent. Without `--output`, the collector verifies every generated file against the retained evidence without writing it. Observed environment: Python 3.11.15, Darwin arm64, Apple LLVM 21.0.0; installed Apple command-line-tool paths are explicit in the producer. Exact commands and versions are retained in records/transcripts. The reviewed `elf_index.py` and `fde_extents.py` are imported only for static ELF/unwind parsing, with their source hashes retained. Whole target identity is checked before parsing or invoking native tools.

Every owner is decoded from its FDE entry, with no resynchronization: each row's original bytes, contiguous addresses, exact final extent and all selected anchor boundaries are checked. CIE/FDE bytes and the unwind-index binding are retained; LLVM dwarfdump independently confirms the decoded unwind range. Direct relative transfers are recomputed from original encodings; in-owner branches must land on decoded boundaries. Each RIP call slot is uniquely resolved to an original relocation record. All exports preserve instructions and data verbatim, with only surplus final newlines normalized. No operand or relocation normalization is used.

The selected operand/data controls flip a real byte in the validator's read view, deliberately bypassing both full-image and body hashes, and require rejection by the intended named byte obligation. Separate FDE-range and relocation-record corruptions exercise exact metadata admission, not runtime semantic equivalence. Truncated and same-size-modified inputs separately fail the public pre-parser identity gate. Repeated captures agree exactly; `validation.json` retains output identities. These are static evidence-admission controls, not target execution or instruction evaluation.

Full required repository tests have not been run for this contribution: the default suite includes captured-instruction evaluators outside the granted static-only scope. This packet remains **Draft**, with the full test gate explicitly unmet. Integration records doctor/verify/catalogue/reproduce and any approved pure-static subset separately; neither packet controls nor a historical suite are substituted for a new full-suite pass. No hosted CI success is claimed.

No captured program, allocator, callback, thread-local state, filesystem operation or network service is executed. No Rust reconstruction, behavior comparison, complete ABI/helper closure, byte-equivalence credit or component gate is claimed; all gates remain false.
