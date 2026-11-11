# RE-011: node #115 EVM arithmetic, EXP, comparison, bitwise and shift opcodes

With this packet, 24 node #115 EVM opcode handlers and every callee on their result paths can be rebuilt as runnable
code: MUL, SUB, SIGNEXTEND, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP and LT, GT, SLT, SGT, EQ, ISZERO, AND, OR, XOR, NOT,
BYTE, SHL, SHR, SAR, CLZ (`0x02`, `0x03`, `0x05..0x0b` without DIV, `0x10..0x1e`). The callees are the two signed
division helpers, the in-place u256 `div_rem`, the ADDMOD core, the 5-limb `div_rem`, the MULMOD core with its limb
compare, and the EXP square-and-multiply helper. One shared interpreter contract (stack, length, gas, spec byte, host
parameter block, result codes `0`, `0x20`, `0x2b`, `0x2c`) is pinned for all of them. One tool proves the
reconstruction against the real machine code of all 32 bodies: 29,200 cases with 0 mismatches, and
130/130 negative controls detected.

- Component ID: `evm` (task RE-011)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No reference source was used.
  The EVM mnemonics come from the opcode index plus the matching semantics.
- Claim status:
  - observation: opcode slots, GOT slots, checked bytes, FDE extents, call sets, interpreter and host offsets, gate
    constants and result codes;
  - observation: the input→output contracts proven on all cases;
  - inference: mnemonics, helper labels, algorithm families, the reading of `+0x1a9` as a spec/hardfork id and of
    parameter `+0x18` as the EIP-160 per-exponent-byte price;
  - unresolved: which hardfork each spec-byte value names, who writes `+0x1a9` and the parameter block, where the
    static gas of these opcodes is charged, and the `esi` immediates of the panic helpers.
- Scope included (four families of one tool):

| family | opcode | body | name (inferred) | callees on the result path |
|---|---|---|---|---|
| ar | 0x02 / 0x03 / 0x0b | `0x298f7f0` / `0x298f9a0` / `0x298f430` | MUL / SUB / SIGNEXTEND | none (inline limb code) |
| dv | 0x05 / 0x06 / 0x07 | `0x298fa00` / `0x298f8f0` / `0x298fa90` | SDIV / MOD / SMOD | `0x29956c0`, `0x2995880`, u256 `div_rem` `0x144dde0` (GOT `0x64dfb80`) |
| md | 0x08 / 0x09 | `0x298fb20` / `0x298fbe0` | ADDMOD / MULMOD | ADDMOD core `0x29fe430`, 5-limb `div_rem` `0x43c1f50` (GOT `0x64e6f50`), MULMOD core `0x43bfc80` (GOT `0x64e6dd8`), limb compare `0x43be000` |
| ex | 0x0a | `0x298f6a0` | EXP | power helper `0x29fcfb0` |
| ex | 0x10..0x1e | `0x2998720` LT, `0x29986b0` GT, `0x2998e00` SLT, `0x2998a90` SGT, `0x2998630` EQ, `0x2999070` ISZERO, `0x2998fd0` AND, `0x2998f80` OR, `0x2999020` XOR, `0x2998830` NOT, `0x2998ef0` BYTE, `0x2998b80` SHL, `0x2998cc0` SHR, `0x2998870` SAR, `0x2998790` CLZ | | none |

- Scope excluded:
  - the dispatch loop and the static gas charge (none of the bodies charges it);
  - ADD `0x298f5b0` (already covered by `RE-001-node115-guarded-limb-add`) and DIV `0x298f600`;
  - the libc imports, which are modelled by contract;
  - the panic helpers, whose bodies and message texts are checked byte for byte but not executed.

## Reproduce

```
python3 tools/re11_arith_exp_bitwise115.py --out research/work-items/RE-011-arith-exp-bitwise-115
python3 -m unittest tests.test_re11_arith_exp_bitwise115
sha256sum -c research/work-items/RE-011-arith-exp-bitwise-115/MANIFEST.sha256
```

- The tool needs Python 3 and the standard library only, plus `tools/elf_index.py` and `tools/fde_extents.py`.
- It checks the input SHA-256 first, never executes the binary and calls no external program.
- It runs in about 5 min and exits non-zero on any mismatch or any undetected control.
- `--full` also writes `cases-full.tsv` with all 29,200 case rows. Its SHA-256 is recorded in `summary.json`
  (`full_case_table`), and each family's rows are pinned again in `families.<key>.case_rows_sha256`.
- `cases-sample.tsv` keeps every 10th row of each family, plus every non-matching row (there are none).

Generated files: `cases-sample.tsv`, `outcome-classes.tsv`, `not-executed.tsv`, `negative-controls.tsv`,
`constants.json` and `summary.json`. Two regenerations, the second with `PYTHONHASHSEED=777`, `TZ=Asia/Seoul` and an
empty `PATH`, give byte-identical output.

## Evidence

All coordinates are #115 virtual addresses. Every number in the generated files is read from ELF bytes in Python:
`.rela.dyn` RELATIVE and GLOB_DAT entries, `.dynsym` import names, `.eh_frame` FDE extents through
`tools/fde_extents.py`, and section bytes through `tools/elf_index.py`. NOBITS sections are never read.

**Opcode tables.** Both RELATIVE tables `0x6441210` and `0x6441f00` are anchored by the SLOAD slot `0x54`
(`0x2993ff0` / `0x2993bd0`). Both name the same body at `table + 8*op` for all 24 opcodes
(`constants.json`, `<family>.opcode_table_slots`).

**Shared handler contract** (all 24 handlers):
- The interpreter is in `rdi`. The stack base is at `+0x28` and the word count at `+0x30`, as little-endian 32-byte
  words. EXP also reads the remaining gas at `+0x188` and the host (`rsi`) `+0x250` → parameter `+0x18`; SHL, SHR, SAR
  and CLZ read the spec byte at `+0x1a9`.
- SHL/SHR/SAR (`cmpb $0x5,0x1a9(%rdi)`) and CLZ (`cmpb $0xd,...`) return `0x2b` below the gate. The gate is checked
  **before** the stack length.
- If fewer than `arity` words are present, the handler returns `0x2c`.
- Otherwise the length drops by `arity - 1`, the result overwrites the deepest consumed slot, and the handler returns
  0 (EXP: `0x20` when out of gas).
- The callee-saved registers and `rsp` are preserved, and no other interpreter, host or parameter byte changes. Every
  case checks this, so the non-EXP handlers also prove that they leave gas untouched.

**MUL / SUB / SIGNEXTEND** (family `ar`, inline limb code):
- MUL: six full `mul` limb products plus four truncated `imul` products for limb 3, joined by an `add`/`adc` chain:
  `top * second mod 2^256`.
- SUB: `sub` followed by three `sbb`: `top - second mod 2^256`.
- SIGNEXTEND: `cmp $0x1f` plus three `sbb $0` is a full 256-bit `k < 31` test (the word is unchanged otherwise); the
  sign bit is `8k+7` (`lea 0x7(,%rsi,8)`); the mask is built in two 128-bit halves split at `k >= 16`. The arm
  `0x298f596` (`call *0x64df870`) is unreachable after the bound test; reaching it is a boundary, never a result.

**SDIV / MOD / SMOD** (family `dv`):
- MOD tests `b == 0` and skips the divider (`je 0x298f98b`); otherwise it calls `*0x64dfb80` and keeps the divisor copy,
  which holds the remainder.
- `0x29956c0` (signed div): a zero divisor gives 0; negative operands are negated in place; `|a| == 2^255` is detected by
  a `pxor` with `.rodata` `0x455a10` (only bit 127 set) and, with `|b| == 1`, returns `-2^255`; otherwise it calls
  `div_rem`, clears bit 255 and negates when exactly one sign is negative (`xor %bpl,%r15b`).
- `0x2995880` (signed mod): a zero dividend or divisor gives 0; otherwise the remainder carries the dividend's sign.
- `0x144dde0` (u256 `div_rem`, in place, FDE 5,874 bytes): quotient to the numerator slot, remainder to the divisor
  slot; `n < d` by `memcpy` plus `memset`; a one-limb divisor uses the hardware `div`; longer divisors are normalised
  with `bsr`/`shld` and divided with the u16 reciprocal table behind `.got` `0x64dfa58` (RELATIVE `0x944462`), whose
  256 entries all equal `floor(0x7fd00 / d)` for `d = 256..511`.

**ADDMOD / MULMOD** (family `md`):
- The handlers pop two words and write the third slot.
- ADDMOD calls `0x29fe430(out, &a, &b, &n)`: `n == 0` gives 0; without a carry, a sum below `n` is returned unreduced
  (`jb`), otherwise reduced by the u256 `div_rem`; with a carry, the 5-limb numerator `{sum, 1}`
  (`movq $0x1,0x20(%rsp)` at `0x29fe555`) goes to `*0x64e6f50`, which writes the remainder into the modulus slot.
- MULMOD calls `*0x64e6dd8(&a, &b, &n)`: a zero modulus returns without writing; otherwise `a*b mod n` over the full
  512-bit product is written over `n`. The core calls the limb-slice borrow compare `0x43be000` at `0x43c01e2`.
- `0x43c1f50` divides a 5-limb numerator in place and touches exactly 40 bytes of it. A zero divisor reaches
  `0x1681d60`, which loads `attempt to divide by zero` (`0x46f29b`).
- The four panic helpers (add/shl/sub overflow, divide by zero) are checked byte for byte with their message text
  (`constants.json`, `md.panic_helpers`).

**EXP and the power helper** (family `ex`):
- EXP `0x298f6a0` (87 instructions, FDE 333 bytes, one call): `cmp $0x2` (`0x298f6a4`) → `0x2c`; the new count is
  stored at `0x298f6c8`, **before** any gas check; a zero exponent (`je` at `0x298f6ec`) skips the dynamic charge;
  otherwise the byte count is `((255 - lz) >> 3) + 1` (four `bsr`, default `0x7f` at `0x298f706`), multiplied by
  `[[rsi+0x250]+0x18]` (`mulq 0x18(%rcx)`, `0x298f760`); `jo` (`0x298f764`) saturates the cost to `2^64 - 1`.
  `[rdi+0x188] < cost` (`jb`, `0x298f770`) returns `0x20` with the count already popped; otherwise the cost is
  subtracted and `0x29fcfb0(out, &top, &copy)` (`e8` at `0x298f7b1`) writes the power over the exponent slot.
- Helper `0x29fcfb0` (171 instructions, FDE 655 bytes, no calls): four zero exponent limbs store 1; otherwise
  square-and-multiply over the low 256 bits, bit 0 (`test $1,%dl`, `0x29fd16a`) selects the multiply, and the exponent
  buffer is shifted right by one **in place** (`shrd`, `0x29fd123`) until it is zero. The base buffer is only read.

**Comparison, bitwise, shift and CLZ** (family `ex`, 701 instructions, no calls):
- A shift amount must have limbs 1..3 zero and limb 0 `< 0x100` (`cmp $0x100`), else SHL/SHR write zero and SAR fills
  from the sign of limb 3. BYTE is big-endian and gives zero for an index `>= 0x20`. CLZ presets the `bsr` destination
  to `0x7f`, so CLZ(0) = 256. SLT/SGT compare signums before the unsigned four-limb `sub/sbb` chain.
- Only EXP calls (once, the helper); the tool fails if any other `ex` body has a direct or indirect call or jump out.

Human-readable excerpt (objdump, for orientation only; not used by the tool):

```
298f760: mulq 0x18(%rcx)          ; EXP: bytes * per-byte price
298f764: jo   298f7d2             ; -> mov $-1,%rax (saturated cost)
298f770: jb   298f7e5             ; gas < cost -> mov $0x20,%al
2998b80: cmpb $0x5,0x1a9(%rdi)    ; SHL gate -> mov $0x2b,%al
298f98b:                          ; MOD: zero-divisor skip target
```

## Implementation and comparison

- Rust implementation: not yet implemented. The Python model is the executable specification for it.
- The executable reconstruction is pure Python in `tools/re11_arith_exp_bitwise115.py`:
  - `ar`: `ar_apply`, `ar_signextend`;
  - `dv`: `dv_divrem`, `dv_i256_div`, `dv_i256_mod`;
  - `md`: `md_addmod_core`, `md_mulmod_core`, `md_reduce5`;
  - `ex`: `ex_exp_bytes`, `ex_exp_cost`, `ex_power`, `ex_apply`, and `ex_model` (spec gate, arity, EXP gas then power).
- Comparison: one shared concrete x86-64 subset evaluator executes the real #115 bytes of all 32 bodies and fails
  closed on any undecoded form. `memcpy`/`memmove`/`memset` follow their libc contract (overlap in `memcpy` is an
  error); each panic GOT target is a named boundary. One case loop (`evaluate`), one control loop (`controls`) and one
  output writer serve all four families.
- Each handler case compares the result code, the stack length, every stack byte (including slack), the interpreter
  block, the callee-saved registers and `rsp`; `ex` cases also compare the remaining gas and the host and parameter
  blocks. Each direct callee case compares every argument slot, the guard bytes around them, the callee-saved
  registers, and the panic name where one is expected.

| family | cases | mismatches | outcome classes | negative controls |
|---|---|---|---|---|
| ar (MUL/SUB/SIGNEXTEND, 2,000 per opcode) | 6,000 | 0 | 19 | 24/24 (9 model, 15 code) |
| dv (SDIV/MOD/SMOD 1,500 per opcode + 1,500 direct `div_rem`) | 6,000 | 0 | 52 | 24/24 (10 model, 14 code) |
| md (ADDMOD/MULMOD 1,400 per opcode + 800 each direct ADDMOD core / MULMOD core / 5-limb `div_rem`) | 5,200 | 0 | 125 | 18/18 (8 model, 10 code) |
| ex (4,000 EXP + 400 per opcode `0x10..0x1e` + 2,000 direct power helper) | 12,000 | 0 | 132 | 52/52 (23 model, 29 code) |
| input controls | – | – | – | 12/12 |
| **total** | **29,200** | **0** | **328** | **130/130** |

- Model mutants include floor division, `-2^255 / -1` saturation, the remainder sign taken from the divisor, a
  SIGNEXTEND bound of 30, a wrapping ADDMOD sum, a truncated MULMOD product, a 4-limb reduction, a floor/word EXP byte
  count, a charged zero exponent, a wrapped EXP cost, `0 ** 0 = 0`, an out-of-gas exit that keeps the count, swapped
  LT, unsigned SLT, low-limb EQ/ISZERO/NOT, little-endian BYTE, SHR limit 255, SAR saturating to zero, CLZ(0) = 255, a
  shift gate of 4, no gate, and underflow code `0x2b`.
- Code mutants flip one byte each across all 32 bodies (branch senses, `setb`/`setae`, `sbb`→`adc`, carry limb,
  result codes, gate immediates, shift bounds, the `bsr` preset, the helper's loop end).
- Input controls (12): a flipped `.text` byte (digest), an address past `.text`, a truncated ELF, a read inside
  SHT_NOBITS `.bss`, no FDE at EXP + 1, a rewired SHR slot and a rewired MUL slot, a changed checked byte, a call
  planted in the power helper, and out-of-range inputs (stack word `2^256`, spec byte `0x100`, helper exponent
  `2^256`).

Instructions executed (`summary.json` → `families.<key>.covered_instructions`):

| body | executed / total |
|---|---|
| MUL / SUB / SIGNEXTEND | 75/75, 24/24, 95/99 instructions |
| SDIV / MOD / SMOD handlers, signed helpers | 34/34, 43/43, 34/34; 113/113, 96/96 instructions |
| ADDMOD / MULMOD handlers, ADDMOD core, limb compare | 43/43, 44/44, 87/87, 25/30 instructions |
| EXP, power helper | 87/87, 170/171 instructions |
| LT..CLZ (15 bodies) | 701/701 instructions |
| u256 `div_rem` / MULMOD core / 5-limb `div_rem` | u256 `div_rem` 5,325 of 5,874 bytes; MULMOD core 7,805 of 8,909 bytes; 5-limb `div_rem` 5,751 of 6,477 bytes |

`not-executed.tsv` lists the 10 misses of the fully decoded bodies: the two SIGNEXTEND arms that are unreachable
after the bound test (including the `8k` overflow panic call), the limb compare's index-out-of-bounds panic call, and
the alignment `xchg %ax,%ax` at `0x29fd09e` before the power helper's loop head.

## Results and limitations

- 29,200 / 29,200 cases match, and 130 / 130 negative controls are detected (`summary.json`).
- `python3 -m unittest tests.test_re11_arith_exp_bitwise115`: 65 tests OK, 0 skips, no binutils.
- Size: the tool has 2,929 lines and the tests 645. Generated data is about 55.3% of the packet's lines.
- This packet merges two earlier drafts of the same work item (arithmetic families `ar`/`dv`/`md`, and EXP plus
  comparison/bitwise/shift `ex`). Their body sets are disjoint, so nothing was dropped. The evaluator is the superset of
  both (it adds `not r/m8`, `xor r8`, and `movq r/m, xmm` to the arithmetic one); the shared core changes no result.
  The `ar`/`dv`/`md` case rows are byte-identical to the earlier arithmetic tool's full table (pinned SHA-256
  `d86e7ad3ab5026fcbb11e61d73a19f6b3693aca82d447608d47f0923a228324d` over the same rows).
- Bytes never executed carry no claim: 549 bytes of `0x144dde0`, 1,104 bytes of `0x43bfc80` and 726 bytes of
  `0x43c1f50`, mostly overflow and bounds panic tails plus rare long-division correction runs.
- The EXP per-byte price is a runtime parameter and is varied over ten values; which value a running node uses is not
  claimed.
- `bsr` on a zero source is modelled as leaving its destination unchanged with ZF set; EXP's byte count and CLZ(0) rely
  on it.
- Equivalent mutants were replaced: a SIGNEXTEND bound of 32 (extending byte 31 is the identity, so the control uses
  30) and a shift bound raised from `0x100` to `0x200`.
- `0x144dde0` also appears as a GOT target in `RE-011-eth-call-path-115/path-evidence.json`; that file lists it, it
  does not reconstruct it.
- Names such as `div_rem`, "ADDMOD core", "MULMOD core", "limb compare" and "power helper" are labels. Only the
  input→output contracts on the measured buffer shapes are claimed. No PROGRESS gate is requested.

Next question: does DIV `0x298f600` share MOD's zero-divisor skip and the u256 `div_rem` `0x144dde0`, and which code
writes interpreter `+0x1a9` and host `+0x250` → `+0x18`, so that the spec gates (shifts at 5, CLZ at `0xd`) and the
EXP per-byte price can be stated as fork rules?
