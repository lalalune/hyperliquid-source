# RE-001: node115 cache read-route selection and local output projection

Component: foundation / data-cache support. Question: how does the complete helper `0x50db530` select its suffix-dependent backend and route the resulting output?

## New observations

The complete FDE `0x50db530..0x50db92e` has 1,022 bytes / 227 LLVM rows. Existing `RE-001-node115-cache-suffix` identifies callers at `0x595b033` and `0x4ec727a`, but leaves this helper's body and actual I/O behavior unresolved. This packet does not reuse the old suffix-selection result as proof of a codec.

Entry retains incoming RDI as the output address, asks slot `0x64e0948 -> 0x1500c10` to populate stack `+8`, then passes the returned pointer/length words through slot `0x64e0950 -> 0x1500d20`. A zero AL goes through descriptor/opaque error construction and writes raw output word `0x8000000000000000` plus another returned word at `+8`. A nonzero AL retains the pointer/length. An empty length gives scalar zero; otherwise the first byte is compared with `/` to form a one-byte selector. This describes only operands and routing; path validity and actual filesystem effects are not established.

The body prepares a descriptor containing pointer/length, byte 6 and fixed bytes `01 02` plus that scalar, and calls slot `0x64e0938 -> 0x5cab560`. Only raw returned leading byte 9 enters the suffix inspection. A two-byte `..` component bypasses it. For the other nonempty component, the backward byte scan seeks a dot; a dot at the component start is also rejected by the remaining-count test. The bytes after the last selected dot are passed to `0x159fca0` with the original three-byte literal at `0x91c30a`, **`rmp`**, and length 3. Other raw tags, no suitable dot, exact `..`, and a zero comparator result enter the alternative route. This does not assert case folding, a source extension type, UTF-8/path invariants or the imported comparison helper's full semantics.

A nonzero comparison result selects slot `0x64e09b8 -> 0x5ca4d50`; the alternative selects `0x64e09c0 -> 0x5ca4940`. Both receive the original pointer/length and write a local output at stack `+0x58`. They are static bound call targets, not proved codecs or file-read operations. Each returned first qword is subjected to NEG/JNO: its exact raw `0x8000000000000000` pattern takes the non-JNO error-construction handoff, while other values proceed. No source enum label is assigned.

The alternative route builds a descriptor with retained pointer/length and two zero words, then invokes `0x5258780`. The suffix route builds a different descriptor, including byte 1 and word `0x20`, and invokes `0x48c7510` with EDX=0. If that selected backend output first word equals the raw sentinel, distinct opaque helpers build output sentinel-plus-word. Otherwise both routes publish two initial qwords plus six 16-byte chunks and a final qword: the observed output extent is **120 bytes**, with the exact sequential stores retained. It is a raw projection, not a recovered Rust object or schema.

A nonzero retained route word triggers a cleanup-shaped call with pointer/word/EDX=0. The initial provider's first word likewise controls a final such call. Normal return sets RAX to the original output address. The full exceptional tail includes additional conditional cleanup and an unwind boundary; its effects are not closed. All local path conclusions assume normal helper returns, ordinary ABI preservation, valid referenced memory and no interfering aliases. No real path, file, metadata or cache contents are read by this research.

## Before, after and remaining question

Before: the suffix packet establishes selected callers' generated names, but leaves this body opaque. After: this one complete body connects component inspection, original literal material, two backend slots and local output publication. Neither `rmp` nor the backend address proves a serialization format, durable read or file-security policy. The comparison/provider/backend/error bodies remain unknown. Next: close one backend's output contract with independent target evidence before implementing cache compatibility or claiming filesystem behavior.

## Reproduce and verification boundary

Target: node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base: `05bc2de303c05525b71e7e257426e741bc66a390`. All coordinates are linked ELF VAs, ends exclusive; file offsets are derived from authenticated sections. FDEs are unwind-described ranges rather than a complete source-function census. No original source names or high-level types are recovered. New code/prose are independently authored under the project's MIT terms; captured bytes retain original rights. No unlicensed inferred source is used.

From repository root, with the pinned artifact materialized:

```sh
python3.11 -B research/work-items/RE-001-node115-cache-read-routing/collect.py
python3.11 -B research/work-items/RE-001-node115-cache-read-routing/collect.py --output work/RE-001-node115-cache-read-routing-fresh
```

The output directory must be absent. Without `--output`, the collector verifies every generated file against the retained evidence without writing it. Observed environment: Python 3.11.15, Darwin arm64, Apple LLVM 21.0.0; installed Apple command-line-tool paths are explicit in the producer. Exact commands and versions are retained in records/transcripts. The reviewed `elf_index.py` and `fde_extents.py` are imported only for static ELF/unwind parsing, with their source hashes retained. Whole target identity is checked before parsing or invoking native tools.

Every owner is decoded from its FDE entry, with no resynchronization: each row's original bytes, contiguous addresses, exact final extent and all selected anchor boundaries are checked. CIE/FDE bytes and the unwind-index binding are retained; LLVM dwarfdump independently confirms the decoded unwind range. Direct relative transfers are recomputed from original encodings; in-owner branches must land on decoded boundaries. Each RIP call slot is uniquely resolved to an original relocation record. All exports preserve instructions and data verbatim, with only surplus final newlines normalized. No operand or relocation normalization is used.

The selected operand/data controls flip a real byte in the validator's read view, deliberately bypassing both full-image and body hashes, and require rejection by the intended named byte obligation. Separate FDE-range and relocation-record corruptions exercise exact metadata admission, not runtime semantic equivalence. Truncated and same-size-modified inputs separately fail the public pre-parser identity gate. Repeated captures agree exactly; `validation.json` retains output identities. These are static evidence-admission controls, not target execution or instruction evaluation.

Full required repository tests have not been run for this contribution: the default suite includes captured-instruction evaluators outside the granted static-only scope. This packet remains **Draft**, with the full test gate explicitly unmet. Integration records doctor/verify/catalogue/reproduce and any approved pure-static subset separately; neither packet controls nor a historical suite are substituted for a new full-suite pass. No hosted CI success is claimed.

No captured program, allocator, callback, thread-local state, filesystem operation or network service is executed. No Rust reconstruction, behavior comparison, complete ABI/helper closure, byte-equivalence credit or component gate is claimed; all gates remain false.
