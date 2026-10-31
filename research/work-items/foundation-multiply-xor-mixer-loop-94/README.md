# foundation-multiply-xor-mixer-loop-94: what does the multiply-xor mixer loop window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 102-byte FDE window with ten padding bytes, the two-stream multiply-xor fold rule with its exact loop exits, the independent emulator re-verification (5,062 cases, zero mismatches), the exact incoming-call scan result (zero direct sites), and the single relocation slot naming the window.
- Excluded: what the buffer holds, what the seeds and xor key mean, the identity or purpose of any caller (there is no direct one), any wider mixer family, and any claim about which source-level hash or checksum this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a loop that folds a buffer from both ends with two 128-bit multiplies per step. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x16488e0`, no open pull request title mentions it or multiply-xor-mixer-loop, and its bytes overlap nothing in packets #1–#81.

## Scout note

The round-12 scout note listed this window (backup B2, the last unbuilt round-12 item) with FDE `[0x16488e0, 0x1648946)`, 102 bytes, 10 padding bytes, zero direct callers, one naming slot `0x57709e8`, and nearest claimed window three-way unsigned clamp `0x15e4f70` (packet #16) `0x63970` away. Every element verified exactly, including the full loop body, both exit branches, the zero direct sites, and the single naming slot. No numeric correction to the scout's numbers was needed. Two phrasing points are reconciled explicitly: the scout's compressed per-step summary ("rcx ^= rax, r9 ^= r10") glosses the two mov steps — rcx is first loaded with the high half of the second product and then xored with its low half, and r9 is first loaded with the high half of the first product and then xored with its low half — the full register trace below is equivalent, not a correction. And the scout's "zero calls" describes the window body (no call opcode inside it), while the incoming scan independently finds zero direct sites — the two statements agree. One further observation, not a scout deviation since the scout did not claim it: unlike most packets, this window does NOT open with `endbr64`; its first instruction is `mov %rcx,%r9`.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_multiply_xor_mixer_loop.py --check research/work-items/foundation-multiply-xor-mixer-loop-94/evidence.json
python3 -m unittest tests.test_foundation_multiply_xor_mixer_loop -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x16488e0 --stop-address=0x1648950 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its ten padding bytes. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x20bf4` (this window) and `0x20c08` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x20bf4` describes `[0x16488e0, 0x1648946)`, 102 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Ten `int3` bytes follow: the next FDE starts exactly at `0x1648950` (record at `.eh_frame+0x20c08`, range to `0x1648999`). The unwind-index stride is therefore 112 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window does NOT open with `endbr64` (an observation, not a scout deviation).
- GNU objdump prints this window under a nearest-symbol label with a `0x395f520`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: two-stream multiply-xor fold, no calls, three branches

Inputs (System V order): `rdi` = base pointer, `rsi` = length-like value, `rdx` = seed B, `rcx` = seed A, `r8` = xor key. Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x16488e0` | `mov %rcx,%r9` | Accumulator A = seed A |
| `0x16488e3` | `mov %rdx,%rcx` | Accumulator B = seed B |
| `0x16488e6` | `movabs $0x7ffffffffffffff0,%r11` | Loop-bound mask |
| `0x16488f0` | `and %rsi,%r11` | `r11 = rsi & mask` (multiple of 16) |
| `0x16488f3` | `je 0x164893f` | Zero bound → final fold |
| `0x16488f5` | `and $0xf,%esi` | Low nibble of the length |
| `0x16488f8` | `add %rdi,%rsi` | Backward-stream base = `rdi + (rsi & 0xf)` |
| `0x16488fb` | `nopl 0x0(%rax,%rax,1)` | Alignment nop |
| `0x1648900` | `lea (%rsi,%r11,1),%rax` | Meeting bound = backward base + `r11` |
| `0x1648904` | `cmp %rax,%rdi` | Forward pointer vs bound |
| `0x1648907` | `jae 0x164893f` | Pointers met → final fold |
| `0x1648909` | `xor 0x8(%rdi),%r9` | A ^= forward high qword |
| `0x164890d` | `mov -0x8(%rsi,%r11,1),%rax` | Backward high qword |
| `0x1648912` | `xor %r8,%rax` | Key xor |
| `0x1648915` | `mul %r9` | Unsigned 128-bit product 1 |
| `0x1648918` | `mov %rax,%r10` | Save product 1 low half |
| `0x164891b` | `xor (%rdi),%rcx` | B ^= forward low qword |
| `0x164891e` | `mov -0x10(%rsi,%r11,1),%rax` | Backward low qword |
| `0x1648923` | `xor %r8,%rax` | Key xor |
| `0x1648926` | `mov %rdx,%r9` | A = product 1 high half |
| `0x1648929` | `mul %rcx` | Unsigned 128-bit product 2 |
| `0x164892c` | `mov %rdx,%rcx` | B = product 2 high half |
| `0x164892f` | `xor %rax,%rcx` | B ^= product 2 low half |
| `0x1648932` | `xor %r10,%r9` | A ^= product 1 low half |
| `0x1648935` | `add $0x10,%rdi` | Forward step |
| `0x1648939` | `add $0xfffffffffffffff0,%r11` | Backward step (−16) |
| `0x164893d` | `jne 0x1648900` | Bound not exhausted → next step |
| `0x164893f` | `xor %rcx,%r9` | Final fold |
| `0x1648942` | `mov %r9,%rax` | Result into `rax` |
| `0x1648945` | `ret` | |

Rule, with `L = rsi & 0x7fffffffffffffff` (the mask clears bit 63; the low nibble is folded into the backward-stream base, so `base2 + r11` at entry equals `rdi + L`):

- If `rsi & 0x7ffffffffffffff0 == 0`, return `seedA ^ seedB` with no step.
- Else, with `A = seedA`, `B = seedB`, `p = rdi`, `r11 = rsi & 0x7ffffffffffffff0`, `base2 = rdi + (rsi & 0xf)`, repeat:
  - `bound = base2 + r11`; if `p >= bound` (unsigned), stop;
  - `A ^= [p+8]`; `(hi1, lo1) = ([bound-8] ^ key) * A` (unsigned 128-bit);
  - `B ^= [p]`; `(hi2, lo2) = ([bound-16] ^ key) * B`;
  - `A = hi1 ^ lo1`; `B = hi2 ^ lo2`; `p += 16`; `r11 -= 16`;
  - until `r11 == 0`.
- Return `A ^ B`.

Step count: `ceil(L/32)` steps for `L >= 16`, else 0. The forward stream advances `+16` per step while the backward stream retreats `−16`, so the two streams meet in the middle; near the meeting point they may overlap — for example, at `L = 48` the second step reads the middle chunk from both streams (see the worked edges). The loop conditions prove every read stays inside `[rdi, rdi+L)`; the emulator sweep below additionally asserted no out-of-buffer read on every run.

Worked edges (hand-computed from the trace above, key `0` unless noted):

- `n = 0` or `n = 5`, seeds `A = 0x1111`, `B = 0x2222` → `0x3333` (no step).
- `n = 16`, buffer qwords `[1, 2]`, `A = 3`, `B = 5` → `6`: `A = 3^2 = 1`, product `2*1 = 2` → `A = 2`; `B = 5^1 = 4`, product `1*4 = 4` → `B = 4`; `2^4 = 6`.
- `n = 32`, buffer qwords `[1, 2, 3, 4]`, `A = 3`, `B = 5` → `8`: one step over the far chunk (`[base+16]`, `[base+24]`), then the meeting guard exits (`p = base+16 >= bound = base+16`).
- `n = 48`, buffer qwords `[1, 2, 3, 4, 5, 6]`, `A = 3`, `B = 5` → `77`: step 1 gives `A = 6`, `B = 20`; step 2 re-reads the middle chunk (`[base+16]`, `[base+24]`) from both streams and gives `A = 8`, `B = 69`; `8^69 = 77`.
- `n = 16`, buffer qwords `[0, 3]`, `A = 2^64−1`, `B = 0` → `0xFFFFFFFFFFFFFFF6`: the first product is `3*(2^64−4)`, whose high half (`2`) folds into the result — the high half is load-bearing, not discarded.

### Independent re-verification (the heavy caveat, discharged)

Because a loop with two 128-bit multiplies is heavier than the usual single-gate bar, the decoded rule was re-verified against an independent byte-level emulator before this packet was written: the window bytes were decoded with Capstone and executed by a small interpreter (mov/movabs/and/lea/cmp/xor/mul/add/branches/ret, with ZF/CF tracking and a bounds-checked buffer) against the closed-form rule in the checker. The interpreter derives every operand from the Capstone decode, so it is independent of the rule's transcription — a misread register, displacement, or multiply order would surface as a mismatch.

- **5,062 cases, 0 mismatches.** Domain: effective lengths `0..1024` exhaustive × 2 seed sets (2,050 runs); 3,000 random runs with effective length ≤ 2048 and edge seeds (`0`, `1`, `2^64−1`, `2^63`, `0x8000000000000000`, `0x7fffffffffffffff`); 12 raw-length variants with bit 63 set (same effective length, exercising the mask). Every run asserted all reads inside the effective-length buffer.
- The emulator script itself is NOT committed: it needs Capstone, which is not in the standard library, and the packet checker is stdlib-only by design. Instead, 8 fixed emulator-generated vectors (lengths 0, 16, 17, 32, 33, 48, 64, 100, with fixed seeds and buffers) are recorded in `evidence.json` and replayed by the checker's `--check` path, so the emulator's results remain replayable from the packet alone.

### Incoming calls: zero direct sites, not a census

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites whose rel32 lands on the window start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. No caller FDE is therefore retained, and the packet has 7 files, not 8.

### Data edge: one naming relocation slot

One relocation record names this window as addend: `R_X86_64_RELATIVE` at slot `0x57709e8` in `.rela.dyn` (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). It is reported as a slot list only; no meaning is claimed for it, and its presence does not identify the window's provenance.

## Inferences

- The window is labeled "multiply-xor mixer loop" for convenience. The label is an inference from the observed operations, kept separate from the rule above.
- The length-like input, the two seeds, and the xor key are read as a buffer fold (hash-like), but no hash, checksum, or source-level function is claimed — the bytes show a fold, not its purpose.
- The window is heavy for the easy-packet bar; it is bound only because its full rule locks exactly and survived the 5,062-case emulator re-verification, not because it is small.

## Unknowns

- What the buffer holds, what the seeds and xor key mean, and whether the length input is a byte count, an element count scaled elsewhere, or something else entirely.
- Whether any indirect caller or tail-jump entrant reaches this window beyond the zero direct sites found.
- What the single naming relocation slot is used for, and whether the window belongs to a wider mixer family.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the single naming relocation does not identify the window's provenance.
- The emulator sweep covers effective lengths up to 2048 plus bit-63 raw-length variants; it does not cover astronomically large effective lengths, which the closed-form rule handles by masking but which no buffer can materialize.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
