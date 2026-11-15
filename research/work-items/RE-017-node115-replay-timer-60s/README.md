# RE-017: selected 60.0 timer conversion (#115)

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are ELF virtual addresses. This extends #6623's selected replay timer branch and the generic conversion context in `RE-008-abci-step-observer-flush-115`; neither established the concrete conversion result for this call site. It is a static, conditional observation, not replay completion.

## Finding

At `0x515233b` the caller loads the double at `0x459718`, whose authenticated bits are `0x404e000000000000`, and calls the pointer in relocation slot `0x64e0f70`. The static `R_X86_64_RELATIVE` relocation points to `0x15ed960`. Assuming the dynamic slot is resolved according to that relocation, this positive finite input follows the bit-decode branch. Its exponent is `0x404`, so `0x15edae7` takes the `<0x433` path. Its 53-bit significand shifted right by `0x33-0x04 = 47` gives `60`. The fractional significand is zero after the corresponding shift and mask, so the rounding, carry and remainder paths return `rax=60`, `edx=0`.

The caller computes `rax * 1,000,000,000 + edx`, saturates it at `0x7fffffffffffffff`, then splits by 1,000,000,000 using multiply-high and a shift before passing the result to the helper via slot `0x64e0f78`. On the established return values, the unsaturated value is `60,000,000,000`, and the split is `60, 0`. This supplies the concrete interval pair for the second timer comparison. It does not by itself prove that helper's date arithmetic, system clock units, timer eligibility, scheduling or runtime reachability.

## Reproduction and limits

Run `python3 research/work-items/RE-017-node115-replay-timer-60s/verify.py`. It authenticates the target and checks five anchors with five one-byte mutation controls. `windows.txt` contains `/usr/bin/objdump -d --x86-asm-syntax=intel` excerpts and `relocations.txt` the `readelf -rW` lines. The input-specific integer reasoning is reviewable independently and does not run the captured target. No general claim about NaN, negative, fractional or large inputs is made; no linkage substitution or interference is ruled out by static bytes alone.
