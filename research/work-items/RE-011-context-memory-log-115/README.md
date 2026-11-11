# RE-011: node #115 EVM context, block, memory-range and log opcodes rebuilt and proven

With this packet, 27 node #115 EVM opcode bodies can be rebuilt as executable code from their opcode-table slots, as
one tool with three parts: the 19 execution-context and block reads (ADDRESS .. BLOBHASH, CALLDATALOAD, POP, GAS), the 3
memory-range bodies (KECCAK256, CODECOPY, MCOPY, with the shared memory-growth routine they call) and the 5 log bodies
(LOG0..LOG4). For each body the packet fixes the check order, the result codes, the interpreter / host / memory /
bytecode field layout it reads and writes, the gas formulas and every reachable panic site. One pure-Python
reconstruction per part agrees with an evaluation of the real #115 machine code on 16,100 byte-derived cases
(0 mismatches), and 84 negative controls (wrong reconstructions, corrupted code bytes, out-of-range inputs) are
all detected.

- **Component ID:** `evm` (work item RE-011, EVM execution)
- **Target release and full SHA-256:** Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Source commit:** main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`
- **Claim status:** behaviour reconstructed and compared case by case against a concrete evaluation of the #115
  machine code. EVM mnemonics, the "transaction type" meaning of host `+0x1f1`, fork names of the spec-byte steps and
  field names are inferences (see Inferences). Opcode `0x4b` is left unnamed (`OP4B`).
- **Scope:** slots of the RELATIVE opcode tables `0x6441210` and `0x6441f00` (both name the same body for every
  opcode below, each table anchored by its SLOAD slot `0x54`):

  | Part | Opcodes | Bodies | Files |
  | --- | --- | --- | --- |
  | context-reads | `0x30 0x32 0x33 0x34 0x35 0x36 0x38 0x3a 0x41 0x42 0x43 0x45 0x46 0x48 0x49 0x4a 0x4b 0x50 0x5a` | 19 | `context-reads-*` |
  | memory-range | `0x20 0x39 0x5e` (KECCAK256, CODECOPY, MCOPY) | 3 | `memory-range-*` |
  | log-emit | `0xa0..0xa4` (LOG0..LOG4) | 5 | `log-emit-*` |

  Out of scope:
  - opcode `0x44` PREVRANDAO (`0x2b95670`), owned by an existing packet; its slot is only checked;
  - the memory-growth routine `0x45244c0` (selected by `RE-021-callframe-input-115`): the memory-range part runs it
    for real as a dependency and compares its effects, but claims no new coordinates for it; the log part stubs it
    through its `.got` slot;
  - who fills the host / context block, and static gas (not charged inside these bodies).

## Reproduce

```
python3 tools/re11_context_memory_log115.py --out research/work-items/RE-011-context-memory-log-115
python3 -m unittest tests.test_re11_context_memory_log115
python3 tools/re11_context_memory_log115.py --full --out <dir>    # every listing row instead of the sample
```

- Standard library only, plus the shared parsers `tools/elf_index.py` and `tools/fde_extents.py`. The tool checks the
  input SHA-256 first and fails on a mismatch, never executes the binary and calls no external program.
- Every number and list in the evidence files comes from ELF bytes read with `struct`: section headers (NOBITS
  sections excluded from VA mapping), `.rela.dyn` RELATIVE and GLOB_DAT entries, `.dynsym`/`.dynstr`, `.eh_frame` FDE
  extents and `.text` bytes.
- Two runs with different `PYTHONHASHSEED` and `TZ` produce byte-identical output.
- The three `*-cases.tsv` and the instruction listings are committed as the header plus every 16th row. The SHA-256
  and row count of each full listing are pinned in `summary.json` `full_listings`; `--full` regenerates them, and the
  unit test regenerates everything in-process and compares every committed byte.

## Evidence

All addresses are #115 virtual addresses; `rdi` is the interpreter block, `rsi` the host (context) block. Each part's
`*-constants.json` holds its opcode-table slots, FDE extents and code SHA-256 per body, the checked byte patterns with
their meaning, `.got` slots and the field offsets the reconstruction uses.

### Shared machinery

- **Dispatch.** For every opcode in scope, `table + 8*opcode` is a RELATIVE relocation to the same body in both
  tables.
- **Stack contract.** `[rdi+0x28]` is the stack base and `[rdi+0x30]` the word count. Push bodies compare the count
  with `0x400` for **equality** (`je` → `0x2d`); pops fail with `0x2c`; spec-byte gates read `[rdi+0x1a9]` and fail
  with `0x2b`. Words are four little-endian limbs.
- **Evaluator.** One concrete x86-64 evaluator (decoder + machine) runs every body. Only the case regions are mapped
  (interpreter, host, memory record and buffer, bytecode record, blob list, stack window), so a read at a
  wrong offset fails the case. Stubs are contract stubs named per part: libc `memcpy`/`memmove`/`memset` (checked by
  their `.dynsym` names), the buffer reserve `0x5be8d40`, the log part's allocator / list grow / memory-expansion
  `.got` slots and every panic slot (a boundary whose location record in `rdi` is compared).

### context-reads (19 bodies, `context-reads-*`)

- Interpreter fields: ADDRESS `0x2997f50` reads `+0x78..+0x8c`, CALLER `0x2997ef0` `+0x8c..+0xa0`; 20-byte fields are
  a dword plus two qwords, each `bswap`ped, i.e. the big-endian value of the 20 bytes. CALLVALUE `0x2998290` copies
  the 32-byte word `+0x58..+0x78`; GAS `0x2997eb0` pushes the u64 `+0x188`; CODESIZE `0x2998240` pushes
  `[[+0x120]+0x50]`.
- Calldata: `+0x38` selects a direct slice (`+0x40` pointer, `+0x48` length) or a view into a shared buffer at
  `[+0x10]` (length `end - start` saturated at 0, `sub`/`cmovae` `0x2997bb8`). CALLDATALOAD `0x2997a50` saturates
  the offset to u64, copies `min(32, len - off)` bytes through the GLOB_DAT `memcpy` slot `0x64df508` into a zeroed
  frame buffer and stores the big-endian, zero-padded word; the shared view's counter `+0x10` nets to 0.
- Host fields: ORIGIN `+0x1c8`, COINBASE `+0xa8` (20 bytes); TIMESTAMP `+0x50` and NUMBER `+0x30` (32 bytes);
  GASLIMIT `+0x90`; CHAINID `+0x258` gated `>= 6`; BASEFEE `+0x98` gated `>= 8`; BLOBBASEFEE u128 `+0x10` if bit 0
  of `+0x0`, gated `>= 0xb`; OP4B `+0xa0` gated `>= 0xe`.
- GASPRICE `0x2999780`: u128 `+0x130`; when byte `+0x1f1 >= 2` and byte `+0xe0 != 0`, `min(that, sat128(u64 +0x98
  + u128 +0xf0))` (`adc`/`cmovb` `0x29997b5`, `cmp`/`sbb`/`cmovb` `0x29997c8`).
- BLOBHASH `0x2999830`: gate `>= 0xb` before the empty-stack check; saturated u64 index; the big-endian hash at
  `[+0x190] + 32*index` only when `+0x1f1 == 3` (`0x2999874`) and the index is below `+0x198`, else 0.
- POP `0x2995df0`: count 0 → `0x2c`, else `count-1`.

### memory-range (3 bodies, `memory-range-*`)

1. **MCOPY `0x29971e0`**: `0x2b` when spec `< 0xb`; `0x2c` when length `<= 2`; then pops 3 **before** any operand
   check; a wide length → `0x24` before gas; gas `ceil(len/32) * params[+0x40]` saturating; `len == 0` → ok without
   checking `dst`/`src`; wide `dst`/`src` → `0x24` after the charge; growth to `ceil(sat(max(src,dst)+len)/32)` words
   above `+0x170`; borrow flag `-1`, bound panics, overlap-safe `memmove`, flag restored to 0.
2. **CODECOPY `0x2997fb0`**: no gate; same pop/width/charge order with `params[+0x28]`; growth from `mem_off + len`; a
   wide code offset saturates; the bytecode record panics when `+0x50 > +0x40`; offset at or past the code length →
   zero-fill after an explicit `end <= mem_len - base` check; otherwise copy then zero-fill the tail with **no**
   memory-length bound check.
3. **KECCAK256 `0x29982d0`**: underflow at length `< 2`; the result overwrites the size slot; charge
   `ceil(size/32) * params[+0x48]`; size 0 stores the immediate `c5d24601…5d85a470` (checked equal to Keccak-256 of
   the empty string); otherwise offset width, growth, three overflow panics, shared borrow `+1/-1` and the in-binary
   sponge (absorb `0x633a380`, squeeze `0x633a460`, permutation `0x633a000`, rate `0x88`) run for real; the digest is
   stored big-endian.
4. **Growth routine effects** (run for real): `total = sat(words*params[+0x50]) + sat(words^2)/params[+0x58]`
   (divisor 0 panics); word count and cost are stored **before** the gas check, so a memory out-of-gas (`0x21`)
   leaves `+0x170`/`+0x178` updated with gas unchanged; reserve when capacity is short, zero-fill, length update or
   truncation.

### log-emit (5 bodies, `log-emit-*`)

- LOG0..LOG4 `0x29926f0`, `0x2993350`, … (all five in `log-emit-constants.json` `functions`; 170 / 224 / 251 / 271 /
  293 instructions, one `ret` each).
- Order: static flag `[rdi+0x1a8]` → `0x28`; fewer than two words → `0x2c`; pop offset and length; a wide length →
  `0x24`; charge `sat(len * params[+0x30]) + k * params[+0x38]` (the multiply by k panics through `.got` `0x64df870` on
  overflow) against `+0x188` (`0x20` when short); a wide offset → `0x24`; memory expansion through `.got` `0x64e6de0`
  when `ceil((off+len)/32) > +0x170`; the data is copied into a fresh owned bytes value; **then** the k topic words
  are checked (short → the data is dropped through vtable `+0x20` and `0x2c` returned).
- Topics are stored big-endian in a `k*32` buffer; a 0x50-byte record (topics vec, bytes value with vtable
  `0x6441d98` when empty, 20-byte address from `+0x78`) is appended to the host log list `+0x270` cap / `+0x278` ptr /
  `+0x280` len (grow through `.got` `0x64dfa48`).

## Implementation and comparison

`tools/re11_context_memory_log115.py` holds one shared ELF image, decoder, evaluator and case stream, then three
parts, each with its own pure-Python reconstruction (`rd_model`, `mr_model`/`mr_step`/`mr_expand`,
`lg_model`/`lg_gas_cost`), harness (`*_run_case`, `*_compare`), deterministic case generator, static evidence and
negative controls. `generate()` runs the three parts and writes one combined `summary.json`.

Each case compares the result code or panic location record, the stack length and every byte of the mapped stack
window, the rest of the interpreter block, every region that must stay unwritten (host, bytecode, blob list,
parameters, code), the memory record and buffer bytes (memory part), the appended log record, topics and data (log
part), and the callee-saved registers plus `rsp`.

| Part | Cases | Mismatches | Negative controls detected |
| --- | --- | --- | --- |
| context-reads | 6,000 | 0 | 35 / 35 |
| log-emit | 6,000 | 0 | 26 / 26 |
| memory-range | 4,100 | 0 | 23 / 23 |
| **total** | **16,100** | **0** | **84 / 84** |

Negative controls per part are in `*-negative-controls.tsv`: model mutants (e.g. little-endian addresses, ungated
or shifted gates, wrapping view length, GASPRICE without the cap or with `max`, BLOBHASH for any type, MCOPY forward
overlap or swapped operands, CODECOPY without the zero tail, LOG topics little-endian, cost wrapping instead of
saturating, topic count + 1, no static check), one-byte code mutants (bounds, displacements, gates, result codes,
type bounds, the GASPRICE carry, the KECCAK256 pad byte) and input
controls (a flipped `.text` byte failing the digest and an address past `.text`).

## Results and limitations

- 16,100 cases, 0 mismatches; 84 / 84 negative controls detected.
- Instruction coverage (per-part `*-summary.json`): context-reads 487/487, log-emit 1,105/1,105
  instructions before the landing pads, memory-range 443/484 handler instructions (the rest are unwind and
  panic-adjacent paths) plus 391 executed instruction addresses of the growth routine and sponge.
- `python3 -m unittest tests.test_re11_context_memory_log115`: 22 tests OK, 0 skips.
- Merge note: two source drafts both covered 17 context bodies; the context-reads draft had more cases per body
  (about 316 versus 160) and is the only one kept. The other draft's 8 control-flow bodies (STOP, JUMP, JUMPI, PC,
  MSIZE, JUMPDEST, INVALID, undefined) are left out because a separate RE-011 packet (stack and control flow)
  already covers them; opcode `0x44` is left out as above.
- Values are runtime state; which values a running node holds and who writes the host block are not claimed.
- CALLDATALOAD's null data pointer and null view base are not constructed. CODECOPY and KECCAK256 have no bound
  check against the memory length; cases with memory shorter than the word count show the write past `mem_len`,
  which the growth invariant normally prevents. The 4 padding bytes of the log record are not compared.
- No PROGRESS gate is changed.

### Inferences (separate from the observations)

- Mnemonics come from the opcode index plus matching EVM semantics (20-byte addresses, EIP-1559 GASPRICE, EIP-4844
  BLOBHASH and EIP-7516 BLOBBASEFEE at the same spec step, EIP-5656 MCOPY, LOG0..LOG4 topic counts).
- Host `+0x1f1` is presumably the transaction type (only `>= 2` and `== 3` are observed).
- Spec-byte steps 6, 8, 0xb, 0xe presumably map to Istanbul, London, Cancun and a later fork; not proven here.
