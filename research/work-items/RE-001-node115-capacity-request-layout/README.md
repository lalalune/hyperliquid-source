# RE-001: node115 16-byte request sizing and three output layouts

- Task/component: RE-001 / `foundation`, one independent sizing/layout question.
- Sole target: node **#115**, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Included: complete FDE `[0x5c8b8f0,0x5c8b980)`, **144 bytes / 45 native instruction rows**, raw sizing gates, two symbol-bound calls and explicit output/return writes.
- Excluded: allocator implementation or invocation, allocation-size-zero policy, callers, source Result/error names, ownership/alias contracts, Rust reconstruction and runtime comparison. No acceptance gate changes.

## Gap, selection and target qualification

The active #115 scope needs its own function-map and layout evidence. This packet resolves a complete helper's multiplication/size bound, old-word branch and three explicit output forms. The full 280-open-PR inventory in `work/fifth-live-prs.json` had no exact-address or selected capacity-request scope match. Current retained research, source and tools contain no interpretation of this body. Recheck live work before submitting; this screening creates no ownership claim.

A historical machine-code search lead was used only to find a candidate. All #115 addresses, actual FDE, native bytes, displacement targets and dynamic bindings were independently rederived from the authentic #115 input. There is real target-specific instruction ordering and different call-slot evidence; no old release label/address substitution is used as proof. No unlicensed inferred source was consulted or copied. New analysis/code is independently authored; captured bytes retain original rights.

Before: this helper's #115 sizing/output protocol was not recorded. After: one full body establishes its accepted scalar domain and explicit response layouts, with actual imported malloc/realloc symbols and unclosed native behavior. “Capacity”, “size” and “output” are descriptive inferred roles, not recovered source type names.

## Reproduce and draft status

Observed environment: macOS 26.4.1 (25E253), CPython 3.11.15, Apple LLVM objdump 21.0.0. From repository root with the authentic pinned artifact:

```sh
python3.11 -B research/work-items/RE-001-node115-capacity-request-layout/verify.py --negative-controls
python3.11 -B research/work-items/RE-001-node115-capacity-request-layout/arithmetic-check.py
python3.11 -B research/work-items/RE-001-node115-capacity-request-layout/capture.py --output work/node115-capacity-recapture
```

The capture directory must be new; `--objdump` can select another installed LLVM. The producer authenticates the entire binary before creating a private byte-identical snapshot under ignored `work/`. Only installed static LLVM tools read that snapshot. Native path labels are normalized to the repository-relative input name, while instruction and data bytes remain exact. No captured instructions, allocators, compiler, network request, chain action or model call run.

`capture.py` gives the exact `-d` range and `--dwarf=frames` recipe and emits `body.objdump.txt`, `frames.txt`, `evidence.json`. A second collection reproduced all three exactly; mathematical output also reproduces exactly. The verifier adapts the author's own generic ELF evidence checks, freshly authenticated and exercised against #115.

**The required repository full suite has not run under the current authorization. This is a reviewable DRAFT with the full gate unmet.** The integrating operator's allowed static subset is reported separately and is not a full-suite substitute. A maintainer must arrange compliant remaining validation before marking the PR ready. Test/workflow settings are unchanged.

## Actual FDE and symbol evidence

All addresses are linked ELF VAs, ends exclusive, with file offsets resolved from ELF sections. FDE `.eh_frame+0x33afd8` under the observed `zR` pcrel-sdata4 CIE independently gives `[0x5c8b8f0,0x5c8b980)`, agreeing with LLVM frame output. All 144 bytes are decoded once, with no nearest-symbol identity or unwind-stride inference.

The native calls resolve by actual RIP operands and unique **R_X86_64_GLOB_DAT** dynamic symbols:

| Site | Slot | Symbol |
| --- | --- | --- |
| `0x5c8b93a` | `0x64ec890` | `realloc` |
| `0x5c8b956` | `0x64e1570` | `malloc` |

These are static import bindings. They do not certify dynamic interposition, the selected libc implementation or actual allocation outcomes. Neither imported function is executed or modeled by this packet.

## Exact sizing gate

Let N be entry RCX (u64), A be entry RSI (u64), Q be entry RDX, and out be entry RDI. The code preserves out and computes:

```text
S = (N << 4) mod 2^64
bad = ((N >> 60) != 0) OR (S > 0x7ffffffffffffff8 unsigned)
```

MOV instructions between the comparisons and OR preserve the relevant flags/results. The gate is **not** just a wrapping multiplication followed by one signed test.

For all u64 N, acceptance is exactly **N <= 2^59-1**. If N>=2^60, the high-bits test rejects regardless of wrapped S. Below 2^60, S=16*N does not wrap, and the size comparison reduces to `N <= floor((2^63-8)/16)=2^59-1`. `arithmetic.json` retains this algebraic proof and 17 boundary witnesses including zero, both bound neighbors and wrap/sign extremes. They are scalar equation checks, not target execution or a full behavior comparison.

## Calls and explicit writes

If the gate accepts, the code tests A for zero:

- A nonzero: pass RDI=Q and RSI=S to the `realloc` slot.
- A zero: pass RDI=S to the `malloc` slot.

A's numeric magnitude does not otherwise enter the local sizing calculation. Its source role is unknown. The subsequent branch tests returned RAX for zero; no allocator behavior is invented, including when S=0.

Under valid, nonaliasing writable output storage and ordinary normal returns from the imported call, the explicit writes/return-register facts are:

| Path | qword out+0 | qword out+8 | qword out+16 | RAX at RET |
| --- | ---: | --- | --- | ---: |
| Sizing gate rejects | 1 | 0 | Not written by this body | 8 |
| Gate accepts, imported return is zero | 1 | Literal 8 | S | 16 |
| Gate accepts, imported return is nonzero | 0 | Imported return word | S | 16 |

The common store uses out+RAX as an offset: the gate-reject path chooses RAX=8 and S-register zero, while the two post-call paths choose RAX=16. The separate qword store at out+0 writes a zero-extended register 0 or 1. On the nonzero-return path the imported word is stored at out+8 **before** RAX is replaced with 16. Thus the original returned pointer-like word is in memory, not the final RAX value.

“Not written” describes this body's explicit path, not an arbitrary-alias or external-helper preservation guarantee. “Zero imported return” is not named an allocation error: size-zero and API/runtime contracts remain outside the evidence. The source-level tag/error/size/alignment interpretation, lifetimes and full ABI are unproved.

## Verification, controls and limits

Observed static checks authenticate the whole artifact, actual FDE/CIE, complete 144-byte body and 45 instruction rows, six short branches, two indirect-call encodings/RIP slot computations and both unique dynamic bindings. Raw instructions and relocation records are retained unnormalized.

Eight real patched-input controls reject count shift, high-bit shift, size-limit immediate, old-word branch, null-result test, indexed output-store encoding, FDE extent and call-slot relocation. They bypass only the whole-image digest. **The first six reject at the exact body-range hash gate**; the FDE and relocation controls exercise independent structural checks. A separate counterfactual changes the authenticated shift immediate from 4 to 5 and shows count 1's scalar size changes from 16 to 32; it does not execute or simulate either allocator call.

No Rust build, source/binary identity, native request, behavioral test, hosted CI or container result is claimed. The full required repository gate remains unmet, so the PR remains draft. Actual call outcomes, error/source types, runtime caller domain, alias/ownership rules, dependencies and whole-node equivalence remain unknown. All reconstruction gates stay false.

Next question: establish one #115 caller's output consumption and ownership contract before turning these raw layouts into a typed Rust interface.
