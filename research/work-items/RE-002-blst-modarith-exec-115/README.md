# RE-002: node #115 blst 384-bit modular helpers reconstructed as executable integer models

With this packet the behaviour of 16 blst 384-bit field helpers in node #115 (add, sub, halve, shift, multiply by 3/8, conditional negate, `1+i` multiply, sign/parity, and their Fp2 `x` forms) can be written as short big-integer functions, and the claim is checked by interpreting the target's own instruction bytes on 16,000 generated inputs with zero disagreements. 44 negative controls (wrong models, one-bit code corruption, out-of-range inputs) were all detected.

- Component ID: foundation (native dependency provenance; RE-002)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository baseline `0781ce04826eeefd89fe336cb8ea073be0c1de30`; byte-identity of these bodies with blst v0.3.16 assembly is already recorded by the earlier window-table packets, this packet does not depend on that source
- Claim status: observation (interpreted behaviour of listed bodies) and inference (the integer models are the intended semantics)
- Scope included and excluded: the 16 entry points in `functions.tsv`, each bounded by its `.eh_frame` FDE. Excluded: SSE `vec_*` helpers, Montgomery multiply/square, inversion, callers elsewhere in the binary. No progress gate is requested.

## Reproduce

Platform: any host with Python 3.12 standard library; no external programs, the binary is only read.

```sh
python3 tools/node115_blst_modarith_exec.py --out research/work-items/RE-002-blst-modarith-exec-115
python3 -m unittest tests.test_node115_blst_modarith_exec
```

The tool checks the SHA-256 above first, reads `.text` and the FDE table (`tools/elf_index.py`, `tools/fde_extents.py`), and rewrites the five generated files. The output is deterministic (seeded `random.Random`, no clock, no paths). Measured peak resident memory is about 380 MB (the whole binary is read once); run time is about 10 s.

## Evidence

All addresses are virtual addresses in the stripped node #115 `.text`.

| file | content |
| --- | --- |
| `functions.tsv` | per function: entry VA, FDE end, byte length, model kind, cases, mismatches, min/max interpreted instruction count, instructions and bytes reached, SHA-256 of the body |
| `executed-instructions.tsv` | every instruction the interpreter decoded from the bytes, by function (VA, length, decoded form) – a byte-derived listing, not binutils output |
| `sample-cases.tsv` | first six generated inputs per function with step count and result |
| `negative-controls.tsv` | the 44 controls and whether each was detected |
| `measure.json` | `cases` 16000, `negative_controls` 44, `negative_detected` 44 |

Entry points (FDE start): `add_mod_384` 0x5d24a80, `__add_mod_384` 0x5d24ac0 (internal, also entered at 0x5d24adb after its caller has loaded r8..r13), `add_mod_384x` 0x5d24b60, `rshift_mod_384` 0x5d24be0, `div_by_2_mod_384` 0x5d24d00, `lshift_mod_384` 0x5d24d80, `mul_by_3_mod_384` 0x5d24ec0, `mul_by_8_mod_384` 0x5d24f20, `mul_by_3_mod_384x` 0x5d24fa0, `mul_by_8_mod_384x` 0x5d25040, `cneg_mod_384` 0x5d25100, `sub_mod_384` 0x5d251e0, `sub_mod_384x` 0x5d252c0, `mul_by_1_plus_i_mod_384x` 0x5d25340, `sgn0_pty_mod_384` 0x5d254e0, `sgn0_pty_mod_384x` 0x5d25560. Names are the upstream symbol names inferred earlier; the stripped target has no symbols.

## Implementation and comparison

`tools/node115_blst_modarith_exec.py` contains (1) an x86-64 subset decoder/interpreter (ALU group, mov/lea/cmov/push/pop/call/ret/jcc/jmp, shifts, shrd/shld, neg/not/inc/dec/test/xchg, 64- and 32-bit operands, ModRM/SIB) that fetches code only from the ELF bytes, runs on a 4 KiB private memory, and faults on any unsupported opcode, out-of-range access or after 4,000 steps; (2) one integer model per function; (3) a harness that stages operands as little-endian 48-byte limbs (96 bytes for the `x` forms), calls the entry with the System V argument registers, and compares the whole memory image (outputs, untouched canary bytes, return slot), `rsp`, and the callee-saved registers (not for the internal `__add_mod_384`).

Models (all `a, b` reduced modulo `mod`, `mod` < 2^384):

- add/sub: `(a±b) mod m`, including moduli close to 2^384 so the 385th-bit carry path (`sbb rdx,rdx`, `cmovb`) is exercised; `x` forms apply it to both halves of the 96-byte operand.
- `div_by_2`: `(a + (m if a odd else 0)) >> 1`; `rshift_mod_384` repeats it `n` times; `lshift_mod_384` is `a·2^n mod m`, n ≥ 1.
- `mul_by_3` = `3a mod m`, `mul_by_8` = `8a mod m` (and `x` forms per half).
- `cneg(a, flag, m)`: unchanged when the full 64-bit `flag` is zero (a flag of only bit 32 or bit 63 counts as set), else `0` if `a` is zero, else `m − a`.
- `mul_by_1_plus_i`: `(re − im, re + im) mod m`.
- `sgn0_pty(a, m)`: bit 0 = `a & 1`, bit 1 = `2a ≥ m`. `sgn0_pty_x(re, im, m)`: bit 0 = parity of `im` when `re = 0` else of `re`; bit 1 = sign (`2x ≥ m`) of `im` when `im ≠ 0` else of `re`. Even moduli with `a = m/2` are generated to separate `≥` from `>`.

Cases: 1,000 per function from `random.Random("20261108:<name>")`; moduli are the BLS12-381 prime, random 381- and 384-bit odd values, `2^384 − k`, small and even moduli; operands mix 0, 1, 2, m−1, m−2, halves of m, powers-of-two residues and random values; shift counts 1..39; `cneg` flags include 0, 1, 2, 0xff, 2^32, 2^63, 2^64−1.

Negative controls (44): 20 wrong models (no reduction, imaginary half skipped, subtract as add, count off by one, parity ignored, always-add halving, ×2 for ×3, ×7 for ×8, 32-bit flag, bit-0 flag, no zero special case, swapped `1+i`, parity-only and `>` instead of `≥` sign, real-only and wrong-bit sgn0x); 15 one-bit flips in the last byte of an executed instruction; 9 range or structural controls (corrupted binary hash, non-FDE address, unreduced operands, shift count 0 that loops, wild pointers, entry outside `.text`, patched unsupported opcode). The tests additionally cover decoder bytes, flag arithmetic and fault paths.

## Results and limitations

- 16 functions × 1,000 cases = 16,000 cases, 0 mismatches. Interpreted step counts: 28 (`sgn0_pty_mod_384`) to 1,939 (`rshift_mod_384`, n up to 39).
- Reached instruction coverage per function is in `functions.tsv`; branches not taken for every operand class are not claimed beyond the cases generated. `mul_by_8_mod_384` executes 116 steps but only 60 distinct instructions because it calls the shared left-shift helper at 0x5d24e60 three times; the helper's own coverage is counted under the callers' reached-address sets only.
- 44 of 44 negative controls detected; the controls were fixed before the final run, and the two initially undetected ones (a `>` sign mutant and an unreduced-operand control that the function legitimately absorbs) were replaced by generator cases and a stricter input rather than relaxed.
- The interpreter is a verification aid written for this packet; it models only the instructions listed and is not a general x86 emulator. Flags other than CF/ZF/SF/OF are not modelled; parity conditions fault.
- Behaviour for unreduced operands, `n = 0` shifts and moduli ≥ 2^384 is not specified by these models.
- Rust code for these helpers is not yet implemented.

Next question: extend the interpreter to the SSE `vec_select_*`, `vec_is_zero_16x` and `vec_is_equal_16x` bodies at 0x5d25680..0x5d25e00, and to the Montgomery multiply/square entries, then compare against the same integer-model approach.
