# RE-002: node #115 blst 256/384-bit field helpers, executed from image bytes and checked against modular arithmetic

- Component ID: RE-002 (native dependency provenance; field helpers of the linked blst library)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository baseline at packet time; no reference source is used. The arithmetic models are written from the observed instruction semantics and the textbook definitions of the operations.
- Claim status: observation (decoded bytes, executed results) plus inference (names and signatures, taken from the function sizes and from the behaviour the checks establish)
- Scope included and excluded: 22 integer-only helper bodies at `0x5d24be0..0x5d2b506`, plus 4 internal helpers they call. Excluded: the SSE `vec_*` helpers, the Montgomery multiply/square family, and any caller of these helpers.

The packet lets a reader reconstruct what each of 22 blst field helpers computes, with calling convention, preconditions, return value and register discipline, from the node #115 bytes rather than from a source tree. A small interpreter for the integer x86-64 subset those bodies use decodes the bytes and runs them. 22,000 generated inputs (1,000 per helper, moduli of 3 to 384 bits) gave results equal to an independent Python model every time. 49 negative controls (wrong models, corrupted bytes, out-of-range inputs, decoder and digest gates) were all detected.

## Reproduce

Run from the repository root with the authenticated node #115 image in place. Python 3 standard library plus `tools/elf_index.py`; no binutils, no subprocess, the node binary is only read.

```sh
python3 tools/node115_blst_field_ops.py --out research/work-items/RE-002-blst-field-ops-emulated-115
python3 -m unittest tests.test_node115_blst_field_ops
```

The tool first checks the image SHA-256 and stops on a mismatch. It reads only the file-backed `.text` bytes of the window `0x5d24000..0x5d2b600` (VA coordinates), is deterministic (two runs under different hash seeds and time zones produced identical bytes) and peaks at about 120 MB resident. Files in this folder: `windows.tsv`, `decoded.tsv`, `results.tsv`, `controls.tsv`, `sample_cases.tsv`, `measure.json`, `MANIFEST.sha256`.

## Evidence

- `windows.tsv`: entry VA, length and body SHA-256 for each of the 22 helpers and the 4 internal helpers. Each window is decoded linearly by the interpreter's decoder and the instruction lengths tile it exactly; a window one byte shorter is rejected.
- `decoded.tsv`: all 1,094 decoded instructions with their raw bytes (VA, length, hex, normalized text). The subset is `mov add adc sub sbb and or xor cmp test not neg inc dec shl shr lea push call jmp jcc cmovcc ret endbr64`.
- `results.tsv`: per helper, cases run, cases matched, and how many body instructions were executed. All instructions are reached for every helper except `mul_by_3_mod_256`: its last four instructions (`0x5d2b0eb..0x5d2b0fa`, an epilogue) are never executed because the body ends in `jmp 0x5d2b059`, which re-enters the middle of `add_mod_256` and returns through that body's epilogue. That shared tail is an observation; that it is intended is an inference.
- `controls.tsv`: the 49 negative controls and whether each was detected.
- `sample_cases.tsv`: the first two generated inputs and outputs per helper, as a spot check.

Observed calling conventions (System V, 64-bit limbs, little endian). `ret`, `a`, `b`, `p` are pointers: `add_mod_256`, `sub_mod_256`, `add_n_check_mod_256`, `sub_n_check_mod_256`, `add_mod_384x384`, `sub_mod_384x384` take `(ret, a, b, p)`; `mul_by_3_mod_256`, `mul_by_3/8_mod_384`, `mul_by_3/8_mod_384x`, `mul_by_1_plus_i_mod_384x`, `div_by_2_mod_384` take `(ret, a, p)`; `lshift_*`, `rshift_*`, `cneg_*` take `(ret, a, k, p)` with `k` in `rdx` (a full 64-bit flag for `cneg`, a 32-bit loop count for the shifts); `check_mod_256`, `sgn0_pty_mod_384`, `sgn0_pty_mod_384x` take `(a, p)` and return in `rax`. Callee-saved registers and `rsp` are restored and nothing outside `ret` is written in every case.

## Implementation and comparison

`tools/node115_blst_field_ops.py` holds three parts: the byte decoder and interpreter (flags CF ZF SF OF, 64 and 32-bit operand sizes, a memory model that faults outside its windows), the arithmetic models, and the case and control generators. Models, with `p` odd and operands below `p` unless stated:

| helper | result |
| --- | --- |
| `add_mod_*`, `sub_mod_*` | `(a+b) mod p`, `(a-b) mod p`; the `*_n_check` forms also return `1` when the result is non-zero |
| `mul_by_3`, `mul_by_8`, `lshift(k)` | `3a`, `8a`, `a*2^k` mod `p`; `k >= 1` |
| `rshift(k)`, `div_by_2` | `a*2^-k mod p` (add `p` when odd, then shift) |
| `cneg` | `p-a` if the 64-bit flag is non-zero and `a != 0`, else `a` |
| `check_mod_256` | `1` iff `0 < a < p` |
| `sgn0_pty_mod_384` | `(a & 1) | (2 if 2a >= p)` |
| `sgn0_pty_mod_384x` | parity of `a0` (of `a1` when `a0 == 0`) combined with the `2a >= p` bit of `a1` (of `a0` when `a1 == 0`) |
| `mul_by_*_mod_384x` | the operation on both halves |
| `mul_by_1_plus_i_mod_384x` | `(a0-a1, a0+a1)` mod `p` |
| `add_mod_384x384` | 768-bit sum; the low 384 bits unreduced, the high half reduced once by `p` |
| `sub_mod_384x384` | 768-bit difference; `p*2^384` added back when it goes negative |

Cases: 1,000 per helper from a splitmix64 stream (moduli full width, shorter, or small; operands random, edge values `0 1 2 p-1 p-2 (p±1)/2`, `a == b` and `b == p-a` for the add and subtract families, 64-bit flags such as `2^32` and `2^63` for `cneg`). Each case also checks `rsp`, the six callee-saved registers and a guard pattern around the buffers.

Negative controls (49): 22 wrong models (one per helper, e.g. missing reduction, off-by-one shift count, parity-only `sgn0`), 15 single-byte corruptions of the image bytes (`adc` to `sbb`, `cmovb` to `cmovae`, `jne` to `je`, immediate and displacement edits, ...), 7 out-of-range uses (shift count 0 runs away and hits the step limit, operands not below `p`, unmapped destination, tiny stack) and 5 decoder and image gates (undefined opcode, truncated instruction, window length off by one, fetch outside the window, wrong digest). Each is run on 120 cases and counts as detected on any mismatch, fault or ABI violation.

## Results and limitations

Machine-readable counts are in `measure.json`: `cases` 22000, `negative_controls` 49, `negative_detected` 49, `cases_matched` 22000. The 19 unit tests, which regenerate every evidence file and compare bytes, pass without skips.

Limits. The interpreter was written for these bodies and is not a general x86 emulator; it runs sampled inputs, not a proof over all inputs. The models assume the preconditions listed above (odd `p`, operands below `p`, `k >= 1`); behaviour outside them is only probed by the controls. Helper names come from the sizes and semantics, not from symbols in the stripped image. No other caller of these helpers is analysed, and nothing here changes a component gate.

Next question: the Montgomery multiplication and squaring bodies next to these helpers (`mulx` and `adx` variants), which need `mulx`, `adcx` and `adox` added to the decoder.
