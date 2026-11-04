# RE-001: node115 f64 integer-power leaf at 0x63f0080

- Component: foundation utilities (floating-point helper). Bounded static research; **no reconstruction gate requested**.
- Target: node115, 105896032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: none copied. The verification model, equations and documentation are independently authored under root MIT. No inferred unlicensed implementation is copied, and no public source revision is asserted byte-equivalent.
- Claim status: observation (addresses, bytes, FDE extent, seed constant) + inference (decoded semantics). No execution of the capture.
- Question: what is the function whose FDE extent is `0x63f0080..0x63f00c6`, and what exact numeric contract do its bytes implement?

## Summary

The 70-byte leaf at VA `0x63f0080` (FDE extent `0x63f0080..0x63f00c6`, unwind index
135300, CIE `0xca6ed8`, no LSDA) computes the **IEEE-754 binary64 integer power
`x**n` by binary exponentiation (exponentiation-by-squaring)**. It is a true leaf:
`objdump` reports **zero `call` instructions** and no out-of-range control flow.

SysV x86-64 ABI reading: `xmm0` = base (`f64`), `edi` = exponent (`i32`); result in `xmm0`.

This leaf is **immediately before** the already-registered window at `0x63f00d0`
(decimal 104792272, the RE-004 / `research/byte-windows.json` u128→binary64
window). This finding is for the **distinct, unregistered** preceding function.
It is the compiler-builtins `__powidf2` / `llvm.powi.f64.i32` lowering by
behavior; that identity is stated as a lead only — **no byte-window is registered
and no dependency-match credit is claimed here**.

## Measured facts (observation)

| Fact | Value | Source |
| --- | --- | --- |
| FDE extent | `0x63f0080 .. 0x63f00c6` (70 B) | `tools/fde_extents.py --release 115` row, unwind index 135300 |
| Section / CIE / LSDA | `.text` / `0xca6ed8` / none | same FDE row |
| Body SHA-256 | `574d4bd89cb36bd1de100c05ba8760818a422ac4593b514a6fed8d975a09877c` | `verify_powi_leaf.py` |
| Leaf (call count) | 0 | `objdump` grep for `call` |
| Seed constant @ `0x4592b0` (.rodata) | bytes `00 00 00 00 00 00 f0 3f` = `1.0` | `verify_powi_leaf.py` |
| Next function | `0x63f00d0` (unwind index 135301) | FDE table |

Raw disassembly is retained in `63f0080.objdump.txt`.

## Decoded algorithm (inference, anchored to byte offsets)

```
63f0080 movapd xmm1,xmm0      ; xmm1 = base x
63f0084 mov    eax,edi        ; eax = n
63f0086 neg    eax            ; eax = -n, SF = sign(-n)
63f0088 cmovs  eax,edi        ; eax = |n|  (if n>0 take edi; INT_MIN stays INT_MIN)
63f008b test   al,0x1
63f008d je     63f0095        ; bit0 clear -> seed result = 1.0
63f008f movapd xmm0,xmm1      ; bit0 set   -> seed result = x
63f0093 jmp    63f00ac
63f0095 movsd  xmm0,[rip+..]  ; -> 0x4592b0 = 1.0
63f009d jmp    63f00ac
63f00a0 mulsd  xmm1,xmm1      ; base = base*base  (square)
63f00a4 test   al,0x1
63f00a6 je     63f00ac        ; this magnitude bit clear -> skip
63f00a8 mulsd  xmm0,xmm1      ; result *= base
63f00ac shr    eax,1          ; consume next magnitude bit
63f00ae jne    63f00a0        ; more bits -> loop
63f00b0 test   edi,edi
63f00b2 js     63f00b5        ; ORIGINAL n < 0 ?
63f00b4 ret                   ;   no  -> return result
63f00b5 movsd  xmm1,[rip+..]  ;   yes -> xmm1 = 1.0 (0x4592b0)
63f00bd divsd  xmm1,xmm0      ;         1.0 / result
63f00c1 movapd xmm0,xmm1
63f00c5 ret
```

Semantics: `pow(x, n) = Π base^(2^k) over set bits k of |n|`, seeded `1.0`, with a
final reciprocal when `n < 0`. `n == 0` returns `1.0`. The magnitude via
`neg`/`cmovs` is standard `abs` and leaves `INT_MIN` unchanged (the documented
`__powidf2` edge).

## Verification and controls

`verify_powi_leaf.py` authenticates the ELF by SHA-256 **before** any byte read,
pins the 70-byte body hash and the `1.0` seed, then checks a pure-Python model of
the decoded algorithm against:

- an **independent binary-exponentiation** implementation, **bit-exact** on all 84
  grid points (bases `{2, 0.5, -3, 1.5, 10, -1, 7}` × exponents
  `{0,1,2,3,5,8,15,31,-1,-2,-5,-8}`). A naive repeated-multiply reference is
  deliberately *not* used for the exact check because it rounds differently
  (e.g. `10.0**31`), which itself confirms the routine is binary exponentiation,
  not repeated multiply; and
- the mathematical value `x**n` within relative tolerance `1e-12` (84/84).

Negative controls (each must break agreement with `x**n`):

| Control | Mechanism | Result |
| --- | --- | --- |
| seed = 2.0 | corrupt the `1.0` constant in the model | diverges |
| drop reciprocal | remove the `js @0x63f00b2` gate | diverges (negative exponents) |
| `cmovs`→`nop` | patch bytes `0f 48 c7`→`90 90 90` in a copy, re-disassemble | magnitude step gone (`control-1-cmovs-to-nop.objdump.txt`) |
| `js`→`jns` | patch byte `78`→`79` in a copy, re-disassemble | gate inverted (`control-2-js-to-jns.objdump.txt`) |

The two byte-patch controls operate on a scratch copy under ignored `work/` and
are re-disassembled statically; the captured binary is never executed or modified.

## Reproduce

From repo root with materialized LFS inputs and GNU binutils on PATH:

```sh
git lfs pull --include="artifacts/node/115/hl-node"
python3 tools/fde_extents.py --release 115 --output-dir work/fde   # FDE row 135300
objdump -d --start-address=0x63f0080 --stop-address=0x63f00c6 -M intel \
  artifacts/node/115/hl-node                                        # == 63f0080.objdump.txt
python3 -B research/work-items/RE-001-node115-f64-powi-leaf/verify_powi_leaf.py
(cd research/work-items/RE-001-node115-f64-powi-leaf && sha256sum -c MANIFEST.sha256)
```

Observed: `verify_powi_leaf.py` prints `RESULT: PASS` (84/84 positive agreements,
both model controls diverge). No PC/register/memory state of the capture is
advanced; the model is a reading of the disassembly, not a decompilation run.

## Limitations and next step

- This is a single leaf's numeric contract, not a component gate; no gate is
  requested and no `byte-windows.json` entry is added.
- The `__powidf2` / `llvm.powi.f64.i32` identity is a behavioral lead; proving it
  would require building the pinned compiler-builtins revision and a registered
  byte-window comparison (out of scope for this packet).
- `INT_MIN` exponent is noted as the standard `abs` edge; not exercised as a
  float path here.
- Next: enumerate the callers of `0x63f0080` (RIP-relative xrefs) to see whether
  any first-party node arithmetic depends on this builtin, and whether the
  adjacent `0x63f00d0` window and this leaf share a source translation unit.
