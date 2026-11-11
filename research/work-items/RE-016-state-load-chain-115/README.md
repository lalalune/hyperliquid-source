# RE-016: node #115 state-load chain loader 0x3c12800, boundary 0x3c13520 and builder 0x3c13610 as one reconstructed flow

With this packet, the whole node #115 path that turns a looked-up `0x27a8`-byte state value into the final `0x42c8`-byte
boxed state can be rebuilt as one Rust flow: the one-time-init gate, the `i64::MIN` rejection, the error arm that frees
three buffers, the allocation and its failure arm, the `box[0x28] == r15` assertion, and the exact post-load patch of
the box (saturating `+1` of `box[0x18]`, the `[0x20]/[0xdf0]/[0xef8] = [0x30]` copies, the `[0x10e8]`, `[0x3e28]`,
`[0x3ee0]` clears, `[0x39b0] = 2`, three sub-object initialisers). The reconstruction (`model()` in the tool) is
compared with the real machine code of all four functions (loader, boundary, builder and the already reconstructed
materializer `0x3c2e860`, run for real) in 12,000 cases with 0 mismatches, and all 43 negative controls are detected.

- Component ID: `abci` (work item RE-016, state materializer call chain; entry route also reported by `RE-017-abci-loader-handoff-115`)
- Target release and full SHA-256: `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: main `0781ce048` (no source; binary-only)
- Claim status: reconstruction of the normal and failure behaviour of the three functions as evaluated on #115 machine code. The helpers (prep `0x4468c20`, string producer `0x38dbd80`, lookup `0x422e410`, drop glue `0x3932230`, sub-object initialisers, allocator, composer, panic entries) are stubs; their meaning is not claimed. All role names are inferences.
- Scope:
  - Included: complete FDEs loader `[0x3c12800, 0x3c12af5)` (757 bytes, 182 instructions), boundary `[0x3c13520, 0x3c13609)` (233 bytes, 66 instructions) and builder `[0x3c13610, 0x3c136ed)` (221 bytes, 51 instructions); every call site and its slot/target; the stack frame arithmetic that links the callers' frames to the composer arguments; the entry slot `0x64e7728` and its single call site `0x2b41f2d`; the real materializer body `0x3c2e860` is executed inside the chain.
  - Excluded: the bodies of the stubbed helpers, the landing pads (their cold targets are listed in `calls.tsv`, not evaluated), and the function containing the entry call site `0x2b41f2d`.
  - Context, owned elsewhere: `RE-017-abci-loader-handoff-115` maps this chain's Location boundaries and GOT slots (observation only); `RE-016-state-materialize-3c2e860-115` reconstructs the materializer. Neither reconstructs the loader, the boundary's two arms or the builder's allocation protocol.

## Reproduce

Working directory: repo root. Python 3, stdlib only, plus `tools/elf_index.py`, `tools/fde_extents.py` and the merged `tools/re16_state_materialize115.py` (its evaluator and materializer evidence). No external program is called, and the binary is never executed. The tool needs about 350 MB and 75 s.

```
python3 tools/re16_state_load_chain115.py --out research/work-items/RE-016-state-load-chain-115
python3 -m unittest tests.test_re16_state_load_chain115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The tool refuses to run unless the input SHA-256 equals the value above. `MANIFEST.sha256` lists every file here except itself.

## Evidence

All numbers come from ELF bytes read with Python (`struct`); `objdump` output is not used by the tool. Coordinates are virtual addresses.

Observed (static):
- `.rela.dyn` RELATIVE slots: `0x64e7728 -> 0x3c12800` (loader), `0x64e9628 -> 0x3c13520` (boundary), `0x64e73a0 -> 0x3c13610` (builder), `0x64e9630 -> 0x3c2e860` (materializer). Slot call sites found by scanning every `ff 15` / `ff 25` in `.text`: loader slot `0x2b41f2d` (one), boundary slot `0x3c128a2` (one, inside the loader), materializer slot `0x3c13665` (one, inside the builder), builder slot `0x2add95b 0x2cc19ea 0x3c135c2 0x5646ba2` (three other callers exist; they are not part of this flow). See `constants.json`.
- 24 byte-exact checked windows (`constants.json`, `checked_bytes`): the `rax == 1` tests, the `neg; jo` pair, the `inc` + `cmovne` saturation, the `0x42c8` / `0x27a8` size immediates, the 16-bit `movw` clears, the frame subtraction.
- `calls.tsv` lists all 41 call sites of the three FDEs with slot, resolved target, role and normal / landing-pad region. `instructions.tsv` lists 299 instructions with an executed flag: 120 of 123 loader body instructions, 52 of 52 boundary and 38 of 39 builder body instructions run; the 4 that do not run are the `jmp`/`ud2` after panic stubs, which end the evaluation by design.

Reconstructed flow (`model()`, `flow.tsv` shows one symbolic trace per case class):
1. If dword `[0x64f01d8] != 0`, call the slow path (slot `0x64df9f0`, `rdi = 0x64f01d8, esi = 1, rdx = loader rsp`) once.
2. `prep(out = rsp, in = &A copy, r15 = A[3])` returns four words P. `P0 == 2^63` is the only value that sets OF in `neg` and panics through slot `0x64df830`.
3. `name(rsp + 0x38, 0x6476768)` returns `(cap, ptr, len)`; `lookup(ptr, len, 0x64767a8)` is called inside the boundary. Return `rax == 1` is the error arm; any other value (0, 2, `u64::MAX`) is the ok arm.
4. Error arm: free B's buffer if `B0 != 0`, drop glue on `B + 0x18`, free P's buffer if `P0 != 0`, return `(1, error)`; the loader then panics through the unwrap entry (`slot 0x64df6a0`, message length `0x2b`) with the error value.
5. Ok arm: copy P (32 bytes) and B (48 bytes) to the boundary frame (`stack -0x120`, `stack -0x100`) and call the builder with the looked-up state. The builder runs the materializer with those two addresses as composer arguments, allocates `0x42c8` bytes (failure: alloc-error entry with align 8 and size `0x42c8`), copies the result, frees the `0x27a8`-byte input (`size 0x27a8, align arg 0`).
6. Loader: free the name string if its cap is non-zero; `assert_eq(box[0x28], r15)` (failure: slot `0x64e1e68`); apply the patch list in the summary above; free A's buffer if its cap is non-zero; return the box pointer.

Inferred: the names above; that `lookup` is a keyed lookup (it receives a pointer, a length and a constant); that `(cap, ptr)` pairs are heap buffers (they are passed to a size-carrying free).

Analysis was complete for the three FDEs; the helpers are limited to their call interface.

## Implementation and comparison

Implementation is a pure Python `model()` plus a concrete x86-64 evaluator (reused from the merged `tools/re16_state_materialize115.py`; this packet adds only the `66 c7 /0 iw` decode form). No Rust path is claimed yet; the model is written so each branch maps to one Rust `match` arm. Cargo.lock / two-build results: not applicable (no Rust build).

Comparison per case: ordered symbolic call trace (every stub call with decoded arguments), terminal panic entry and its argument words, return value, the full `0x42c8`-byte box (also at the assertion failure, before the patch), the input buffer after the composer consumed its sub-value, the argument records unchanged, callee-saved registers and `rsp` restored.

12,000 deterministic cases (`mat.make_case` byte streams plus 16 chain modes in an 18-slot cycle (`ok` has three slots): ok, ok-once, ok-allocfail, ok-assertfail, ok-name0, ok-sat, err, err-b0, err-p0, err-both0, neg-overflow, ok-lookup2, ok-lookupmax, ok-p0, err-once, ok-ramp). `cases.tsv` records every second case; all 12,000 are compared.

Negative controls (43, all detected): 17 model mutants (wrapping `inc`, missing once gate, inverted assert, no assert, ignored overflow, inverted lookup test, swapped error-arm frees, skipped error free, name freed unconditionally, wrong source for `[0x20]`, 4-byte clear, skipped sub-object init, wrong sub-object offset, flag value 3, wrong malloc size, skipped input free, swapped composer arguments); 22 one-byte code mutants in the three functions (comparison immediates, displacements, size immediates, call targets, branch conditions, the frame subtraction); a flipped `.text` byte (input hash check); an address past `.text`; two wrong slot targets rejected by the static checks.

## Results and limitations

Machine-readable metrics: `summary.json`, `measure.json` (12,000 cases, 0 mismatches, 43 of 43 controls detected, 16 outcome classes). Per-class counts are in `outcome-classes.tsv`.

Limits:
- Helper behaviour is not reconstructed; the chain is proven only relative to the stub interface (arguments and return registers). If a stubbed helper writes into the box, the box patch could interact with it.
- The three other builder callers (`0x2add95b`, `0x2cc19ea`, `0x5646ba2`) and the function around `0x2b41f2d` are not analysed.
- No gate is requested; the `abci` component remains partial.

Next question: reconstruct the lookup `0x422e410` (the producer of the `rax == 1` arm and of the `0x27a8`-byte state) and the function containing `0x2b41f2d`, which supplies A and B.
