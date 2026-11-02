# RE-001: node94 global mutex/key construction and TLS return paths

- Component: `foundation`; one bounded continuation of the previous TLS state/mutex-fallback packets: how is their exact global base and thread-key destination initialized, and what do the visible failure paths return?
- Target: node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Included: `[0x555aa30,0x555aaa7)` (119 bytes) and its construction helper `[0x552a6c0,0x552a77c)` (188 bytes): **307 bytes / 2 complete FDEs**. Six imported-symbol PLT stubs are anchors, excluded from that denominator.
- Excluded: callback and prior slow-path bodies, auxiliary-value helper, global initializer callers, startup order, runtime synchronization, Rust reconstruction and target execution. No acceptance gate requested or changed.
- “Initializer”, “base” and “construction” are descriptive research labels, not recovered source declarations or proof that startup invokes this function. No inferred reference source, labels or tests were copied; new code/prose is independently authored, adapting the author's earlier static TLS verifiers. Captured bytes retain upstream rights.

## Selection, prior gap and result

The earlier `RE-001-tls-trylock-fallback-94` packet / PR #1953 identifies `base+0x40` as the argument to imported mutex operations, but leaves its initialization/attributes and the global key's creation unknown. The present packet resolves the construction path for the **same** base `0x59b0de0`, lock address `0x59b0e20`, key destination `0x59b0e5c` and readiness byte `0x59b0e58`.

The complete 598-open-PR inventory in `work/fourth-prs.json` was read for exact new addresses and scope, including `555aa30`, `555aa4a`, `552a6c0`, `59b0de0`, `59b0e5c` and key-creation terms. No prior body claimed these bodies. PR #1953 names mutex initialization as its next unknown; other TLS matches concern unrelated network TLS. This selection is not an ownership claim; recheck before submission.

Before: numeric fields and a fallback call were grounded, but the concrete constructor/key creation path was unknown. After: two complete instruction ranges establish object offsets, imported setup calls, checked versus unchecked results, the key callback address, readiness store and zero/TLS return paths. Source-level types, invocation order, full error contract and lock correctness remain unresolved.

## Reproduce

Observed: macOS 26.4.1 (25E253), CPython 3.11.15, Apple LLVM objdump 21.0.0, optimized build. Work from the repository root with the pinned artifact materialized:

```sh
python3.11 -B research/work-items/RE-001-tls-global-initialization-94/verify.py --negative-controls
python3.11 -B research/work-items/RE-001-tls-global-initialization-94/capture.py --objdump /Library/Developer/CommandLineTools/usr/bin/llvm-objdump --output work/tls-global-recapture
```

The export directory must be new. Another host may supply its installed LLVM objdump. The script calls only the local static disassembler and reads the authentic input; no captured program, instruction evaluator, compiler, networking, chain action or model call runs. Exact `-d` range commands and `--dwarf=frames` export recipe are in `capture.py`. Only the new output directory is written. Paths printed in disassembly are normalized to the repository-relative target label; no instructions, operands or data are normalized.

The verifier checks the whole-input digest, ELF mappings, unique selected relocations, actual FDE/CIE records, complete nonduplicated byte coverage of both interpreted FDEs, original branch displacements and selected RIP-relative targets. It checks 97 retained instruction/prefix lines across bodies and anchors. These are static evidence-population counts, not reconstructed/matched bytes or a function census.

`verification.json` retains a successful check and eight rejected corruptions. `capture.py` regenerates `evidence.json`, `frames.txt` and three `*.objdump.txt` files. A second fresh export reproduced all five generated files exactly. The full capture result is not a native behavior test, hosted CI result or source-build comparison.

## Actual ranges and binding evidence

All coordinates are **ELF VAs**, without a guessed runtime or Ghidra rebase. ELF sections map the two bodies to file offsets `0x5559a30` and `0x55296c0`. The verifier resolves these mappings, rather than assuming one global VA-to-file rule.

| FDE section offset | Actual range | Bytes |
| --- | --- | ---: |
| `.eh_frame+0x2cf908` | `0x555aa30..0x555aaa7` | 119 |
| `.eh_frame+0x2ca18c` | `0x552a6c0..0x552a77c` | 188 |

Each PC/range is decoded from the original record under the exact observed `zR` CIE (pcrel signed-32-bit PC), then independently confirmed by LLVM frame output. Alignment bytes beyond either exclusive end are not included. Raw FDE/CIE identity, code-range hashes and complete instruction bytes are retained.

The six unique `R_X86_64_JUMP_SLOT` bindings below are checked with both their PLT RIP operands and dynamic symbol records:

| PLT | Slot | Symbol |
| --- | --- | --- |
| `0x56602f0` | `0x5778ea0` | `pthread_key_create` |
| `0x5661180` | `0x57795e8` | `pthread_mutexattr_init` |
| `0x5661190` | `0x57795f0` | `pthread_mutexattr_settype` |
| `0x56611a0` | `0x57795f8` | `pthread_mutexattr_destroy` |
| `0x5660b70` | `0x57792e0` | `pthread_mutex_init` |
| `0x5660430` | `0x5778f40` | `__stack_chk_fail` |

They are static import identities, not an observed dynamic-loader execution. Numeric attribute type 0 below is not replaced with a platform-specific enum name.

## Construction helper: visible stores and error branches

The helper `0x552a6c0` saves its first argument as `base`. Four 16-byte zero stores initially clear bytes `[base,base+0x40)`. It then calls `0x552aa70` twice: `(destination=base+8, source=0x800fb0)`, followed by `(destination=base, source=0x800fb0)`. Those are observed argument values only. The auxiliary helper's copy width, semantics and other effects are outside this packet, so the initial zero stores do **not** prove all 64 bytes remain zero afterward. An explicit later store sets qword `[base+0x30]=0`.

The remainder follows these exact local branches:

1. Pass the address of a stack-local attribute object to `pthread_mutexattr_init` at `0x552a71f`. A nonzero `eax` goes directly to the return-value-1 path at `0x552a728`.
2. On zero, clear `esi` and call `pthread_mutexattr_settype` at `0x552a74d`. Its return value is not locally tested; the next setup passes `base+0x40` and the attribute pointer to `pthread_mutex_init` at `0x552a759`.
3. The return from `pthread_mutex_init` **is** tested. Both its zero and nonzero paths call `pthread_mutexattr_destroy`; those destroy return values are not tested. A zero mutex-init result is followed by `xor eax,eax`; a nonzero result eventually reaches `mov eax,1`.
4. The return paths compare the saved `fs:0x28` canary with its current value. Mismatch calls `__stack_chk_fail`; otherwise the function returns `eax=0` or `eax=1` as above.

The visible local sequence therefore establishes where attributes are requested and which results affect this helper's return. It does not establish that the ignored settype call succeeded, recover the source-level mutex type, prove construction atomicity or define cleanup outside this body. This is not a defect/security allegation: runtime preconditions, error reachability and outer cleanup remain unclosed.

## Global wrapper: base, key, readiness and result

The 119-byte wrapper at `0x555aa30` prepares `rdi=0x59b0de0`, `rsi=0x1e7182`, and clears `edx/ecx` before calling `0x552a6c0` at `0x555aa4a`. It tests the returned **AL**. A nonzero value reaches `xor eax,eax` at `0x555aaa0` and returns zero in RAX. The constructor's return was constrained to EAX 0/1 by its own body above; the wrapper is not assumed to accept arbitrary hidden return conventions.

On zero, the wrapper prepares `rdi=0x59b0e5c` and `rsi=0x555a690` and calls the symbol-bound `pthread_key_create` at `0x555aa61`. Its full `eax` is tested; nonzero reaches the same RAX-zero path. The address `0x555a690` is thus the actual second argument supplied for key creation, not a callback implementation claim. Its body and teardown effects are not newly covered.

Only after the key call returns zero does the wrapper explicitly write byte 1 to `0x59b0e58`. It then computes `rax=fs:0-0x10a0` and tests the current thread's byte at relative offset `-0x10a0+0x330`:

- If that byte is zero, it restores the stack and returns the computed TLS address in RAX.
- If nonzero, it clears `esi`, moves that TLS address to `rdi`, restores the stack and tail-jumps at `0x555aa97` to `0x555a760`. That target's earlier packet establishes its own state transitions; it is an existing boundary, not new coverage here. Its normal return and transitive effects remain the caller's assumptions.

This grounds the observed **zero-on-two-local-failure-branches versus TLS-address/slow-path continuation**. It does not recover a source pointer/Option type or prove the TLS region's lifetime. The wrapper does not explicitly clear readiness on either failure branch and contains no explicit rollback/destroy call there. That observation is limited to this body; it does not prove the prior readiness byte was zero or that called helpers/outer callers provide no cleanup. The key and readiness storage lie in `.bss`; runtime initialization order, repeated/concurrent invocation and other writers are unknown.

The base-plus-`0x40` argument now matches the exact `0x59b0e20` mutex address used in the earlier membership packet; it is not an unrelated generic constructor inferred merely from nearby code. Whether this wrapper actually executes before those uses requires separate caller/order evidence.

## Validation, bounds and next work

Observed verification passes six exact range hashes, two actual FDE/CIE records, all 307 body bytes, 97 retained instruction lines, 17 direct edges, eight short/conditional edges, 12 selected RIP references and six unique dynamic bindings. Exported PLT bytes are anchors and are not counted as first-party reconstruction. No whole-program caller census or module denominator is supplied.

Eight patched-input controls reject constructor zero-store offset, mutex `+0x40`, zero attribute-type instruction, mutex status test, key callback displacement, readiness immediate, FDE extent and key-create relocation. They deliberately bypass only the whole-image SHA gate. **The first six fail exact range-byte hash locks**, rather than semantic execution checks; the last two independently exercise FDE-record and relocation checks. No passing target behavior or native error-path execution is claimed.

No Rust implementation, build, two-build result, normalized-byte comparison, hosted CI, container run or component-gate credit is proposed. Repository-wide checks are the integrating operator's separate results. All gates remain false. Remaining gaps include actual wrapper invocation/order, the auxiliary initialization helper, callback cleanup, imported API error contracts, global writers and threading invariants.

Next question: trace this exact wrapper's incoming call/initialization-order evidence and recover callback `0x555a690` before claiming a complete lifecycle, failure rollback or key teardown protocol.
