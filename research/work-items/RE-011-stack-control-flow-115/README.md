# RE-011: node #115 EVM stack and control-flow opcodes (PUSH/DUP/SWAP, JUMP/JUMPI/PC, DUPN/SWAPN/EXCHANGE) rebuilt and proven

With this packet you can rebuild, as runnable code, every node #115 EVM opcode body that moves the stack or the
instruction pointer. That is 75 bodies:

- PUSH0..PUSH32, DUP1 and DUP3..DUP16, SWAP1..SWAP16 (`0x5f..0x9f`, 64 bodies);
- STOP, JUMP, JUMPI, PC, MSIZE, JUMPDEST and INVALID;
- the one body shared by all 102 undefined opcodes;
- the immediate-operand opcodes DUPN/SWAPN/EXCHANGE (`0xe6..0xe8`).

The two families share one interpreter contract, which the tool checks once: stack base `+0x28`, length `+0x30`,
cursor/ip `+0x118`, spec byte `+0x1a9`, result codes `0x2b`/`0x2c`/`0x2d` and the 1024-word limit. The packet pins
how PUSHn advances the cursor that JUMP/JUMPI/PC read and write, the code-object jump-destination bitmap layout
(`+0x18` bytes LSB first, `+0x28` bit length, `+0x38` code base) and every failure code. One tool evaluates the real
machine code of the 75 bodies in 12,400 cases with 0 mismatches. 1,591 of the 1,594 decoded instructions run. The
3 that do not form a panic arm, and the packet proves it unreachable. 68 of 68 negative controls are detected.

- Component ID: `evm` (work item RE-011, EVM execution)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No reference source is used, and
  no #94 result is reused.
- Claim status:
  - Observation:
    - the opcode-table slots and FDE extents;
    - the interpreter, code-object and memory-object offsets;
    - the result codes;
    - the per-body constants derived from decoded bytes;
    - the agreement of the evaluated machine code with the model in every case.
  - Inference:
    - the EVM mnemonics, taken from the opcode index plus the observed semantics;
    - the halt-reason names of the result codes;
    - the hardfork meaning of the spec-byte gates `0xa` (PUSH0) and `0xe` (`0xe6..0xe8`).
  - Unresolved:
    - who pads the bytecode so that a PUSH at the end of code can read `n` bytes;
    - who builds the jump-destination bitmap;
    - the static gas charge.
- Scope:
  - Included: the RELATIVE slots of the opcode tables `0x6441210` and `0x6441f00` for opcodes `0x00 0x56..0x59 0x5b
    0x5f..0x9f 0xe6..0xe8 0xfe` and the 102 undefined opcodes, the 75 bodies they name, and their FDE extents.
  - Excluded:
    - DUP2 (`0x81` → `0x2995ab0`), which belongs to the merged packet `RE-001-node115-stack-copy`. Its slot is
      checked, but its body is not run.
    - the dispatcher loop, static gas, and every other opcode slot.

| family | opcodes | bodies | rule read from the bytes | failure codes |
|---|---|---|---|---|
| PUSH0 | 0x5f | `0x2997060` | `cmpb $0xa,0x1a9(%rdi)`; `cmp $0x400` + `je` (only == 1024 rejects) | 0x2b, 0x2d |
| PUSH1..32 | 0x60..0x7f | 32 | `cmp $0x3ff` + `ja`; big-endian immediate, cursor += n | 0x2d |
| DUP1, DUP3..16 | 0x80, 0x82..0x8f | 15 | `lea -n(%rax)`; `cmp $(0x3ff-n)` + `ja` (n <= len <= 1023) | 0x2d |
| SWAP1..16 | 0x90..0x9f | 16 | `cmp $(n+1)` + `jb`, no upper bound | 0x2c |
| JUMP / JUMPI | 0x56 / 0x57 | `0x2999580` / `0x2999610` | pop first, saturate, `dest < [code+0x28]` and `bt` on `[code+0x18]` | 0x2c, 0x2a |
| PC / MSIZE | 0x58 / 0x59 | `0x29994f0` / `0x2997550` | `ip - base - 1` / `[[rdi+0x10]+0x28] - [rdi+0x18]` | 0x2d, panic |
| STOP / JUMPDEST / INVALID / undefined | 0x00 / 0x5b / 0xfe / 102 ops | 4 | constant result | 0x01 / 0 / 0x29 / 0x26 |
| DUPN / SWAPN / EXCHANGE | 0xe6..0xe8 | `0x2995e10` / `0x29970a0` / `0x2997120` | gate `0xe`, signed immediate bound, nibble decode | 0x2b, 0x37, 0x2c/0x2d |

## Reproduce

From the repository root, with the Python 3 standard library only (no binutils; the binary is never executed):

```
python3 tools/re11_stack_control115.py --out research/work-items/RE-011-stack-control-flow-115
python3 -m unittest tests.test_re11_stack_control115
```

- The tool first checks the SHA-256 of `artifacts/node/115/hl-node` and fails on any other input.
- It reads the following, with the shared parsers `tools/elf_index.py` and `tools/fde_extents.py`:
  - `.rela.dyn` RELATIVE addends;
  - `.eh_frame` FDE extents;
  - section headers;
  - `.text` bytes.
- It exits non-zero on any of these:
  - a mismatch;
  - an undetected negative control;
  - a not-executed instruction other than the 3 expected ones;
  - a byte-derived constant that disagrees with its family rule;
  - a difference between the two families' interpreter layouts.
- Full case tables are not committed. `*-cases-sample.tsv` keeps every 8th row. `summary.json` pins the SHA-256 of
  each full table (`cases_sha256`) and of the executed-instruction list (`executed_sha256`), and a rerun recomputes
  both.
- Two runs with different `PYTHONHASHSEED` and `TZ` give byte-identical output; the unit tests regenerate with seed 7
  and `TZ=Asia/Seoul`. `MANIFEST.sha256` lists every file here except itself.

## Evidence

All addresses are node #115 virtual addresses, and `rdi` is the interpreter block.

1. **Dispatch** (`constants.json`, `*.opcode_table_slots`):
   - Slot `table + 8*op` names the same body in `0x6441210` and in `0x6441f00`.
   - Each table is anchored by its SLOAD slot `0x54` (`0x2993ff0` / `0x2993bd0`).
   - There are 130 slots for `0x5f..0x9f`, including the excluded DUP2, and 22 slots for the control-flow opcodes.
   - The undefined body `0x2999700` fills the same 102 slots in both tables.
2. **Shared interpreter contract** (`constants.json` → `shared_interpreter_layout`).
   - The PUSH bodies read and advance the cursor at `+0x118`. JUMP/JUMPI write it, and PC/DUPN/SWAPN/EXCHANGE read it.
   - Both families agree on the stack base, length, spec byte, result codes `0x2b`/`0x2c`/`0x2d` and the limit
     `0x400`. The tool fails if they diverge.
3. **PUSH/DUP/SWAP** (`push-dup-swap-functions.tsv`). For each of the 64 bodies the tool decodes the whole FDE extent
   and extracts the constants below, then fails unless they follow one rule per family:
   - the length `cmp` immediate;
   - the DUP `lea -n` bias;
   - the cursor advance (`add $n` / `inc`);
   - the spec gate;
   - the `mov $imm,%al` failure codes;
   - the stack displacements.

   The behaviour:
   - PUSH0 rejects only `length == 1024` (`je`, `0x299706d`), while PUSH1..32 reject `length >= 1024`.
   - PUSHn reads exactly code bytes `0..n-1` after the cursor. The evaluator records every byte read.
   - DUPn uses one unsigned range test, so an underflow returns `0x2d`, never `0x2c`.
   - SWAPn has no upper length check.
   - No body contains a call or an indirect jump.
4. **JUMP `0x2999580` / JUMPI `0x2999610`**:
   - JUMP returns `0x2c` on an empty stack. JUMPI needs two words.
   - Both store the popped length **before** checking (`0x29995ba`, `0x2999661`), so a bad jump still pops.
   - A destination with any high limb saturates to `2^64 - 1` (`0x29995ad`).
   - A destination is valid iff `dest < [code+0x28]` and bit `dest & 7` of byte `dest >> 3` at `[code+0x18]` is set
     (`bt`, `0x29995dd`). Then `ip = [code+0x38] + dest`. Otherwise the result is `0x2a`.
   - JUMPI with a 256-bit zero condition returns 0 with `ip` unchanged (`0x2999675`).
5. **PC `0x29994f0`** pushes `ip - base - 1`. **MSIZE `0x2997550`** pushes `[[rdi+0x10]+0x28] - [rdi+0x18]`.
   - An impossible underflow in either calls the `.got` slot `0x64df848` (a boundary).
   - A full stack returns `0x2d`.
6. **DUPN `0x2995e10` / SWAPN `0x29970a0` / EXCHANGE `0x2997120`**:
   - All three are gated on `[rdi+0x1a9] >= 0xe` (`0x2b` below).
   - The immediate at `ip` is rejected with `0x37` by a **signed** byte compare: `>= 0x5b`, or `>= 0x52` for
     EXCHANGE. So `0x80..0xff` is accepted.
   - DUPN/SWAPN depth is `(x + 0x91) mod 256`: 219 accepted bytes, depths 17..235.
   - EXCHANGE takes the nibbles `q, r` of `x ^ 0x8f` and gives `(q, r+1)` if `q < r`, else `(r, 29-q)`: 210 accepted
     bytes. Every accepted byte yields `a < b`, so its panic arm `0x29971d0..0x29971d8` is unreachable (the 3 rows of
     `not-executed.tsv`).
   - DUPN reports a short stack as `0x2d`; SWAPN/EXCHANGE report it as `0x2c`.
7. **Pinned bytes**: the 50 entries of `checked_bytes` (18 + 32) are read from the ELF and must match.

Human-readable excerpt (objdump, for orientation only; not used by the tool):

```
299706d: cmp  $0x400,%rax      ; je -> mov $0x2d,%al     (PUSH0: equality only)
2995bf4: lea  -0x1(%rax),%rcx  ; cmp $0x3fe,%rcx ; ja    (DUP1: one unsigned range test)
2996dc4: cmp  $0x11,%rax       ; jb -> mov $0x2c,%al     (SWAP16: no upper bound)
29995c0: cmp  0x28(%rcx),%rdx  ; dest < bitmap bits      (JUMP)
29995dd: bt   %r8d,%esi        ; bit dest&7 of byte dest>>3
2995e25: cmp  $0x5b,%dl ; jge -> 0x37 (signed)           (DUPN)
2997142: xor  $0x8f,%rdx       ; EXCHANGE nibbles
```

## Implementation and comparison

- `tools/re11_stack_control115.py` holds one model per family; each is a pure-Python function over u256 words.
  - `ps_model`: one function for PUSH/DUP/SWAP, parametrised by `n`. It returns the result code, the length, the
    cursor, the stack words, and the list of code bytes read.
  - `cf_model`: the control-flow model, with the helpers `cf_is_jumpdest`, `cf_sat64`, `cf_decode_single` and
    `cf_decode_pair`. It returns the result code, the length, the written slots, the new `ip`, or a panic.
- Shared parts, used by both families:
  - the ELF/relocation/FDE image reader;
  - one concrete x86-64 subset evaluator that runs the real code bytes. Unsupported encodings raise, and nothing is
    stubbed.
  - one comparison loop (`evaluate`);
  - one negative-control loop (`controls`);
  - one output writer.
- Every case maps only the reachable stack window plus slack slots, so any other access faults. It compares:
  - the result byte, the length and the cursor/ip;
  - every byte of the stack window;
  - the rest of the interpreter block;
  - the code-object, memory and bytecode regions, which must be unwritten;
  - the code bytes read;
  - the callee-saved registers and `rsp`.
- Cases come from SHA-512 streams with fixed labels:
  - 6,400 for PUSH/DUP/SWAP: 100 per opcode, with length modes around every bound, beyond 1024, edge immediates and
    spec bytes;
  - 6,000 for control flow, weighted toward the branching bodies: valid and invalid destinations, saturation,
    taken/not taken, gate edges, every immediate class.
  - In total 12,400 cases, 0 mismatches, 198 outcome classes (`outcome-classes.tsv`, 161 + 37).
- Negative controls (`negative-controls.tsv`), **68/68 detected**:
  - 28 model mutants, 14 per family. Examples: PUSH0 without its gate, a little-endian immediate, DUP underflow as
    `0x2c`, a SWAP upper bound, a truncated destination, an MSB-first bitmap, JUMP popping late, an unsigned immediate
    compare, swapped EXCHANGE nibbles.
  - 36 one-byte code mutants (17 + 19): gates, `je`→`jae`, bounds, biases, cursor advances, the `bswap` register,
    stack offsets, code-object offsets, the xor key and the result codes.
  - 4 input controls: a flipped `.text` byte (digest), an address past `.text`, and opcodes `0x5e`/`0xa0` outside
    the PUSH/DUP/SWAP family.
- Rust implementation: not yet implemented. The two models are the executable specification for it.

## Results and limitations

- `summary.json`:
  - cases 12,400 (6,400 + 6,000), mismatches 0;
  - instructions executed 1,591/1,594 (1,343/1,343 and 248/251);
  - negative controls 68/68.
- Unit tests: `python3 -m unittest tests.test_re11_stack_control115` gives 21 OK and 0 skips. They include:
  - a forged opcode slot;
  - changed check bytes;
  - a PUSH17 advance byte changed to 16, which only the family rule catches;
  - a forged layout disagreement;
  - a byte-identical regeneration.
- Lengths above 1024 break the interpreter's own invariant. They are used only to expose the shape of each compare
  (PUSH0 `je`, SWAP without an upper bound) and are not claimed to be reachable.
- That `ip` points one past the opcode byte on entry is inferred from PC's `-1` and from the immediate reads.
- Out of scope: the dispatcher, static gas, the bitmap builder, bytecode padding, and the hardfork names of the spec
  gates. No PROGRESS gate is requested.

Next question: which function builds the jump-destination bitmap at code object `+0x18/+0x28` and pads the bytecode,
and does its PUSH-data skip agree with the PUSHn cursor advance reconstructed here?
