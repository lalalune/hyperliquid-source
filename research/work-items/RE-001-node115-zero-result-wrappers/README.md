# RE-001: node115 payload wrappers with an unconditional normal zero result

Component: foundation / lazy-call instrumentation. Question: what do `0x154c2c0` and `0x154c4e0` actually return along their local normal exits, and which payload calls do they wrap?

## New observations

The complete FDEs are `0x154c2c0..0x154c4d9` and `0x154c4e0..0x154c6f9`, each 537 bytes, together 1,074 bytes / 236 LLVM rows. They are one paired protocol question; they are not split into two contributions. No claim that the pair is byte-identical is made.

Both save incoming RSI as the payload pointer and incoming RDI as an object pointer. Byte object `+0x20` equal to zero bypasses instrumentation but still invokes the payload. For a nonzero byte they copy incoming RCX's 8+8+4 bytes, call distinct helpers `0x15d40f0` / `0x15d46d0`, and retain each returned RAX for later guard cleanup. Only incoming EDX's low byte and a qword at captured TLS displacement `-0x488` decide whether the additional table/formatting path is entered. Those tests are observations, not a recovered tracing flag or thread policy.

The additional path calls `0x15d3300`, then passes the copied 20-byte material and an opaque provider result through slot `0x64e0a90`. Raw returned RAX=1 enters descriptor preparation and the formatting-like call through `0x64df4b8`; other values bypass it. A retained count is tested before a cleanup-shaped call using pointer, `count*56`, and EDX=0. The multiplication is a raw machine operation, not a validated allocation bound. Descriptor data, TLS initialization, table ownership and helper behavior are outside the claim. The full exports include all arguments and exception tails.

On their respective normal paths, the wrappers call `0x1544b00` / `0x15444d0` with the saved incoming RSI. Enabled instrumentation additionally calls `0x156f3b0` on the retained guard-like word. Both enabled and disabled paths converge immediately before `xor eax,eax`: at `0x154c467` / `0x154c687`. From that XOR to the respective sole decoded RET at `0x154c47a` / `0x154c69a`, only stack restoration and POP instructions occur; there is no call or write to RAX. The collector independently checks that corridor and the sole RET in each complete owner. Consequently **each ordinary local return has full RAX=0**, irrespective of the payload helper's returned word. The payload call may instead fail, unwind or not return; no global return/exception guarantee follows.

The exception tails have conditional cleanup calls and direct calls to `0x63f0a50`, which the native tool labels `_Unwind_Resume@plt`. This is a retained native annotation; the callee implementation and loader interposition are not qualified here. They are retained as original code, without treating their opaque calls as normal behavior or inventing a C++/Rust catch/result layout. No concurrency abstraction, lock ownership or arbitrary exception closure is recovered.

## Relation to prior labels

`RE-001-node115-tls-lock-id` deliberately leaves its zero-probe callees' results unclassified. `RE-005-node115-key-consumers` and `RE-005-node115-gate-postcheck` also leave `0x154c4e0` internals open, using an equality/verdict label from caller context. The new complete-body fact is narrower and more concrete: this wrapper's ordinary normal result is always zero, while its payload helper remains opaque. Therefore the old role label must not be promoted into proof that this body computes or returns a general equality verdict. This packet does not alter those earlier raw bytes, does not recover the payload's semantic role, and does not interpret zero as a source-language false/success value.

Before: these were unresolved callback boundaries. After: their distinct payload calls, instrumentation gates, guard/table cleanup and shared normal zero-return contract are byte-bound and independently reproducible. Next: recover the actual payload helpers `0x1544b00` / `0x15444d0` and their caller argument layout before assigning semantic predicate names.

## Reproduce and verification boundary

Target: node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base: `05bc2de303c05525b71e7e257426e741bc66a390`. All coordinates are linked ELF VAs, ends exclusive; file offsets are derived from authenticated sections. FDEs are unwind-described ranges rather than a complete source-function census. No original source names or high-level types are recovered. New code/prose are independently authored under the project's MIT terms; captured bytes retain original rights. No unlicensed inferred source is used.

From repository root, with the pinned artifact materialized:

```sh
python3.11 -B research/work-items/RE-001-node115-zero-result-wrappers/collect.py
python3.11 -B research/work-items/RE-001-node115-zero-result-wrappers/collect.py --output work/RE-001-node115-zero-result-wrappers-fresh
```

The output directory must be absent. Without `--output`, the collector verifies every generated file against the retained evidence without writing it. Observed environment: Python 3.11.15, Darwin arm64, Apple LLVM 21.0.0; installed Apple command-line-tool paths are explicit in the producer. Exact commands and versions are retained in records/transcripts. The reviewed `elf_index.py` and `fde_extents.py` are imported only for static ELF/unwind parsing, with their source hashes retained. Whole target identity is checked before parsing or invoking native tools.

Every owner is decoded from its FDE entry, with no resynchronization: each row's original bytes, contiguous addresses, exact final extent and all selected anchor boundaries are checked. CIE/FDE bytes and the unwind-index binding are retained; LLVM dwarfdump independently confirms the decoded unwind range. Direct relative transfers are recomputed from original encodings; in-owner branches must land on decoded boundaries. Each RIP call slot is uniquely resolved to an original relocation record. All exports preserve instructions and data verbatim, with only surplus final newlines normalized. No operand or relocation normalization is used.

The selected operand/data controls flip a real byte in the validator's read view, deliberately bypassing both full-image and body hashes, and require rejection by the intended named byte obligation. Separate FDE-range and relocation-record corruptions exercise exact metadata admission, not runtime semantic equivalence. Truncated and same-size-modified inputs separately fail the public pre-parser identity gate. Repeated captures agree exactly; `validation.json` retains output identities. These are static evidence-admission controls, not target execution or instruction evaluation.

Full required repository tests have not been run for this contribution: the default suite includes captured-instruction evaluators outside the granted static-only scope. This packet remains **Draft**, with the full test gate explicitly unmet. Integration records doctor/verify/catalogue/reproduce and any approved pure-static subset separately; neither packet controls nor a historical suite are substituted for a new full-suite pass. No hosted CI success is claimed.

No captured program, allocator, callback, thread-local state, filesystem operation or network service is executed. No Rust reconstruction, behavior comparison, complete ABI/helper closure, byte-equivalence credit or component gate is claimed; all gates remain false.
