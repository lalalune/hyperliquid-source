# RE-004: signed and nonnegative quantity float conversion

Node #94 has two distinct quantity conversion paths: one floors a signed result at zero, while the other applies a separately rounded `1.0 - factor` and preserves negative results, enabling their reconstruction without conflating these operations.

- Component ID: RE-004 (quantities and rounding).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23` (unlicensed inferred labels only).
- Claim status: observation for bytes, branches, FDE extents and linked Location records; inference for input names and mathematical interpretation; unresolved caller-level meaning and reachable factor domains.
- Scope included and excluded: complete FDE-described bodies at `0x3c06160` and `0x4cda1a0`, including their error arms and conversion decisions. Caller bodies, the panic callee, floating-point environment configuration, node #115 and the visor are excluded. The two bodies are related conversion variants; no call between them is asserted.

## Reproduce

Run at the repository root with Python 3.12.3 and its standard library on Linux x86-64. The script uses `tools/elf_index.py` and `tools/fde_extents.py`, checks the target digest first, and reads but never executes the target. No network is used.

```sh
python3 tools/artifacts.py verify
python3 tools/signed_float_conversion94.py --out research/work-items/RE-004-signed-float-conversion-94
python3 -m unittest tests.test_signed_float_conversion94
python3 tools/catalogue.py --check
(cd research/work-items/RE-004-signed-float-conversion-94 && sha256sum -c MANIFEST.sha256)
```

The generator writes `evidence.json` and `vectors.tsv`; the manifest also covers this README. For human inspection only, GNU objdump 2.42 can display the bodies with `objdump -d -M intel --start-address=0x3c06160 --stop-address=0x3c0620a artifacts/node/94/hl-node` and `objdump -d -M intel --start-address=0x4cda1a0 --stop-address=0x4cda253 artifacts/node/94/hl-node`. The generator and tests do not call objdump or parse its output.

## Evidence

Addresses are ELF virtual addresses; file offsets, complete function bytes, branch destinations and constants are in `evidence.json`. FDE extents are `[0x3c06160, 0x3c0620a)` (170 bytes) and `[0x4cda1a0, 0x4cda253)` (179 bytes). The normal paths end in returns and the sign-error paths end in calls; unwind ranges alone do not prove every possible entry or ownership. Each error arm supplies a different relocation-backed Location record with the same `l1/src/qtys/mod.rs:843:1` suffix. The generator verifies the relocation and omits the original build prefix.

Let `x` be the 64-bit input in `rdi` and `f` the incoming binary64 in `xmm0`. The instructions first test bit 63 of `x` and take the error call when it is set. Otherwise they convert `x` with `cvtsi2sd` and multiply. The second body first calculates `1.0 - f` with `subsd`. Thus the observed input guard is `x < 2^63`, independent of the factor. No product or result store occurs on the high-bit error path.

Both bodies mask the product's sign bit and compare its remaining bits against `0x7fefffffffffffff`. The nonfinite branch uses zero; finite products are bounded using binary64 constants at `0x20acb8` (-2^63) and `0x20a7f0` (+2^63), then `cvttsd2si` truncates toward zero. The upper correction uses the largest binary64 below +2^63 at `0x20a2c8` to produce `i64::MAX` at the upper endpoint. The first body additionally selects zero for any nonpositive signed integer; the second retains the signed integer. The following interpretation assumes the default IEEE 754 round-to-nearest, ties-to-even mode for the arithmetic; `RN` marks each separate binary64 rounding:

```text
if x >= 2^63: error call
p = RN(RN(x as binary64) * f)                # first body
p = RN(RN(x as binary64) * RN(1.0 - f))      # second body
if p is nonfinite: n = 0
else: n = clamp(trunc_toward_zero(p), -2^63, 2^63 - 1)
first returns max(n, 0); second returns n
```

This is an interpretation of the fixed instruction bytes, not target execution. For example, `x=7, f=1.5` yields `-3` in the second path; the first path at `x=7, f=-0.5` yields zero. Conversion to binary64 is itself significant: `2^53+1` rounds to `2^53` before multiplication. The second path's subtraction is separately rounded and is not a fused multiply-subtract.

The mask comparison classifies all 2^64 binary64 bit patterns: clearing the sign gives a value at most `0x7fefffffffffffff` exactly when the exponent is not 2047, irrespective of the fraction. The generator checks 12,288 representative sign/exponent/fraction combinations and records the exact class sizes. This proof concerns the classification of the already computed product, not reachability of every product from valid caller inputs.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No build, Cargo.lock, compiled-byte comparison, normalization mask, helper closure or dynamic target execution is claimed. The 494 vectors compare a mathematical model with manually lifted basic blocks, including taken branch destinations read from the validated image; all 494 agree. This is a hand lift conditional on the checked bytes, not a general x86 emulator or a measurement of the node. Eight offline unit tests check the retained function windows, branch and FDE facts, target digest and corruption controls, boundary cases, and 154 finite model comparisons using exact rational arithmetic with separately rounded binary64 stages. These are controls on the transcription, not proof of full target behavior.

## Results and limitations

The generator checks two entire FDE byte windows, four floating constants, two Location relocations, and ten explicit branch destinations. It records 494 model-versus-lift vectors and 12,288 classification representatives. The sign/exponent argument covers all product bit patterns for the finite test; the two-variable multiplication and its input reachability are not exhaustively proved. The SSE rounding mode and exception settings at callers are not established here. NaN payloads and floating-point exception flags are not modeled. The source-level types, units, indirect callers, panic internals and state effects remain unresolved. No component progress gate is requested.

Next question: establish the actual factor provenance and floating-point mode at independently unclaimed callers before treating either modeled operation as a recovered asset-level rule.
