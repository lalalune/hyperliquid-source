# RE-001: node94 TLS trylock fallback, retry and blocking-call protocol

- Component: `foundation`; one bounded next question from `RE-001-tls-state-membership-94`: what does its unresolved fallback `0x552a500` do after trylock fails?
- Target: node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Included: complete FDE `[0x552a500,0x552a66e)`, **366 bytes / 1 FDE**. Two narrow earlier-caller excerpts and three PLT stubs are anchors, excluded from that denominator.
- Excluded: time/statistics-helper bodies, runtime global initialization, other callers, lock implementation, concurrency correctness, Rust reconstruction and captured-code execution. No progress gate requested or changed.
- Source labels/types and exact allocator ownership/version remain unknown. No inferred reference code was consulted or copied; new checker/prose is independently authored and adapts the author's earlier TLS evidence scripts. Captured bytes retain their original rights.

## Gap, selection and result

The prior membership packet establishes that it passes the lock address minus `0x40` to this helper, but explicitly leaves its behavior and locking guarantees unknown. The present packet establishes its own pause/retry loop, later trylock, blocking mutex call and visible bookkeeping. It **does not** turn an unchecked pthread return into a proven lock-ownership guarantee.

Selection freshly examined all 589 open PR bodies using `gh pr list -R lalalune/hyperliquid-source --state open --limit 1000 --json number,title,body`; none mentioned `552a500`, `59b0de0`, `59b0e20` or the selected fallback scope. Existing TLS caller/membership packets remain anchors, not new claims. Recheck live work before submission; this inspection creates no ownership claim.

Before: the fallback was an unresolved call boundary. After: one fully retained function provides exact numeric retry gates, atomic counter updates, named imported calls and the point where the blocking return goes unchecked. Source enum names, global setup and full lock correctness remain open.

## Reproduce

Observed platform: macOS 26.4.1 (25E253), CPython 3.11.15, Apple LLVM objdump 21.0.0 (optimized build). From repository root with the authentic pinned artifact materialized:

```sh
python3.11 -B research/work-items/RE-001-tls-trylock-fallback-94/verify.py --negative-controls
python3.11 -B research/work-items/RE-001-tls-trylock-fallback-94/capture.py --objdump /Library/Developer/CommandLineTools/usr/bin/llvm-objdump --output work/tls-fallback-recapture
```

The capture output must be a new directory; earlier evidence is not overwritten. On another host, pass its installed LLVM objdump. The scripts use only Python's standard library and the local static disassembler; no target binary, instruction evaluator, node, chain action, network request or compiler runs.

`capture.py` preserves the exact commands and range choices: LLVM `-d --start-address=... --stop-address=...` for the six ranges in `evidence.json`, plus `--dwarf=frames` and selection of the actual FDE. It exports three disassembly files, `frames.txt` and `evidence.json`. The path label is normalized to the repository-relative artifact path; instruction/data bytes and operands are not normalized. An observed fresh export to `work/tls-fallback-export-complete` reproduced all five generated files exactly. `verification.json` retains the independent check and seven negative-control results.

The verifier authenticates the whole input, parses the ELF sections, rejects duplicate section names, checks every retained instruction byte, requires complete nonduplicated byte coverage of the selected FDE, decodes that FDE under the exact observed CIE, recomputes direct/conditional branch and RIP-relative targets, and resolves unique selected relocations. It does not use a nearby symbol annotation as a function identity.

## Boundaries, caller and imported symbols

All coordinates are **ELF virtual addresses**, not guessed runtime/Ghidra addresses. The section map places the function at file offset `0x5529500`. FDE `.eh_frame+0x2ca120` has the actual pcrel signed-32-bit PC and range for `[0x552a500,0x552a66e)`, agreeing with independent LLVM frame output. Its CIE is the retained `zR` record at section offset zero. Alignment bytes after `0x552a66e` are not part of the 366-byte body.

The earlier caller anchor at `0x555a4ed` loads `r12=0x59b0e20`. At `0x555a640`, it constructs `rdi=r12-0x40`, calls this helper at `0x555a645`, then stores byte 1 at `0x59b0e48` and rejoins the earlier protocol. Register preservation across intervening calls relies on the ordinary ABI; the whole caller was covered by the prior packet and is not re-claimed here.

The helper saves its input as `base=r12` and computes `lock=base+0x40` in `rbp`. Static PLT/GOT resolution identifies:

| PLT VA | Slot | Unique relocation | Symbol |
| --- | --- | --- | --- |
| `0x5660e70` | `0x5779460` | `R_X86_64_JUMP_SLOT` | `pthread_mutex_trylock` |
| `0x5660220` | `0x5778e38` | `R_X86_64_JUMP_SLOT` | `pthread_mutex_lock` |
| `0x5660430` | `0x5778f40` | `R_X86_64_JUMP_SLOT` | `__stack_chk_fail` |

The RIP-relative load-address calculation and indirect jump operands are verified against the symbol-bearing slots, rather than trusting disassembler comments. A fourth selected relocation at `0x576d968` is `R_X86_64_RELATIVE` with target ELF VA `0x552a8f0`; the body calls through this slot at `0x552a5fd`. Its source-level name and behavior are unresolved.

## Observed retry gate

At `0x552a525`, the function obtains the address `0x5799c70` and compares its dword with 1. Exactly 1 bypasses the initial pause/retry loop and enters the later path at `0x552a5a0`. No source configuration name, CPU count or mode enum is recovered.

Otherwise a local qword counter starts at zero and execution goes directly to `0x552a55f`:

1. Execute `pause`, then load byte `[base+0x68]`.
2. If that byte is zero, call `pthread_mutex_trylock(lock)`. A zero return goes directly to the success counter update at `0x552a577`.
3. A nonzero byte or failed trylock loads qword `[0x5788178]`. Continue the loop when it equals all-ones (`-1`) **or** is signed-greater-than the current local counter. The counter increments modulo 2^64 before the decision is used. Otherwise enter `0x552a5a0`.

The first pause/possible trylock occurs before consulting the qword limit. Signed comparison and the separate all-ones sentinel matter; this is not an unsigned clamp or a proof of bounded retries for all runtime mutations/overflows. The qword's file-backed `.data` value is 600, retained as `5802000000000000`; its runtime value may change. The dword at `0x5799c70` is `.bss`, whose runtime meaning/value is unknown. A nonzero byte at `base+0x68` suppresses the loop's trylock attempt, but does not by itself bypass the loop.

On initial-loop trylock success, the function increments qword `[base+0x18]` and goes to its canary/return epilogue. It does not explicitly set byte `base+0x68` on that path.

## Later trylock, blocking call and visible bookkeeping

The later path first calls opaque helper `0x552ab70` with stack pointer `rsp`, then `0x552aa70` with destination `rsp+8` and source `rsp`. These values' time/statistics interpretation is an inference; their source types and units are not established.

It then sets `ebx=1` and executes `lock xadd dword [base+0x24],ebx`. `ebx` receives the old dword and is incremented once, producing the post-increment candidate modulo 2^32. This is an observed x86 atomic RMW; no source-language memory-order mapping is claimed.

The function calls `pthread_mutex_trylock(base+0x40)` again:

| Result | Visible continuation |
| --- | --- |
| Zero | Atomically subtract 1 from dword `base+0x24`, increment qword `base+0x18`, and go to the epilogue |
| Nonzero | Call `pthread_mutex_lock(base+0x40)`, then store byte 1 at `base+0x68` and atomically subtract 1 from dword `base+0x24` |

There is **no test of `eax` between the blocking mutex call at `0x552a5dc` and the store at `0x552a5e1`**. The visible continuation is therefore conditional on a named API call having been made, not proof that it returned success. No defect or vulnerability is alleged: valid initialization, API preconditions, error reachability and the caller contract remain unresolved.

After the blocking-call path, the function calls through slot `0x576d968` with `rsp+8`, calls `0x552aa70` to populate `rsp+0x10`, and calls `0x552aac0` with destination `rsp+0x10` and source `rsp`. It increments qword `[base+0x10]`, calls `0x552aaa0(base,rsp+0x10)`, and compares the value at `base+8` with `rsp+0x10` through `0x552aa80`. A negative returned `eax` causes `0x552aa70(base+8,rsp+0x10)`; otherwise that copy is skipped. These helper effects are not closed by naming them as time operations.

Finally it compares dword `[base+0x20]` **unsigned** with the saved candidate from the atomic increment. If the stored value is lower, it stores the candidate; otherwise it preserves the stored value. The max-like update is only a local instruction fact: no race-freedom, logical waiter-count invariant, overflow safety or true maximum-concurrency claim is made.

All returning paths check the saved `fs:0x28` canary against its current value. A mismatch calls the symbol-bound `__stack_chk_fail` stub at `0x552a669`. The primary FDE contains no unlock call. Whether the imported calls and opaque helpers return under all conditions is not established by static exports.

## Verification and limits

Observed checks pass whole-input identity, six retained range hashes, the actual FDE/CIE record, complete 366-byte body coverage and 114 retained instruction/prefix lines across body and anchors. Eighteen direct edges, ten short/conditional branches, seven selected RIP references and four selected relocations reproduce. Those counts describe this evidence population, not a complete caller census, reconstructed bytes or whole-node completion.

Seven mutations are rejected after bypassing only the outer artifact digest: initial dword comparison, spin sentinel, atomic-counter offset, blocking-call displacement, high-water-field offset, FDE extent and trylock relocation. The **first five are rejected by exact range-byte hash locks**, not semantic emulation. The FDE and relocation mutations exercise independent structural checks. `verification.json` retains the specific rejection reasons. No native-execution or behavioral-test result is inferred from these controls.

No Rust implementation/build, two-build comparison, normalized byte comparison, model-backed behavior, hosted CI or container run is claimed. Repository-wide checks are reported by the integrating operator separately. Source names, unit types, full lock attributes/initialization, global writers, transitive helpers and the API error contract remain unknown. All component gates stay false.

Next question: validate the mutex initialization and attributes associated with this exact `base+0x40` object, then recover `0x552a8f0` and the associated value helpers before interpreting the bookkeeping fields as elapsed-time statistics or completed lock ownership.
