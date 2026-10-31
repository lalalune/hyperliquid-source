# foundation-keyed-multiply-xor-mixer-94: what does the keyed multiply-xor mixer window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 70-byte FDE window with ten padding bytes, the keyed three-multiply rule with its exact operand layout and GOT indirection, the exact incoming-call scan result (two direct sites in two caller FDEs), and the zero-naming-relocation edge.
- Excluded: what the mixed value means, what the key table is, what reads the result, any wider mixer family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a keyed multiply-xor mixer that folds two unsigned 128-bit products and a constant through a third keyed multiply. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x399c600`, no open pull request title mentions it or keyed-multiply-xor-mixer, and its bytes overlap nothing in packets #1–#89.

## Scout note

The round-14 scout note listed this window (ranked #2) with FDE `[0x399c600, 0x399c646)`, 70 bytes, 10 padding bytes, two direct callers, no naming relocation, and nearest claimed window cursor walk loop `0x3c1d690` (packet #46) `0x281090` away.

**Material scout correction — the input loads are qwords, not dwords.** The scout summary described `[rsi+0xc]` and `[rsi+4]` as dword reads, implying a 16-byte input block. The encodings say otherwise: `48 8b 46 0c` and `48 8b 46 04` carry the REX.W prefix, so all four input loads are 64-bit qwords at `rsi+0`, `+4`, `+8`, `+12` — a 20-byte input span read through overlapping windows. The corrected rule below is what the checker locks and what the emulator sweep verified; the scout's dword framing is not used anywhere. All other scouted elements verified exactly (FDE range, 70-byte body, 10 padding bytes, both callers and their FDE ranges, no naming relocation).

**Second scout refinement — the key table is reached through a GOT pointer, not read directly.** The first instruction loads a pointer from the GOT slot at `0x576e3e0`; `k0` is the qword at that pointer, `k1` the qword 8 bytes past it. Both the slot and the table are runtime-filled, so no key value is claimed anywhere; the rule is parameterized by `(k0, k1)`.

## Mixer-family justification, stated head-on

This window resembles packets #29 (multiply/xor mixer), #43 (multiply-mix divide-by-61 store), and #82 (two-stream fold with 128-bit multiplies) in that it multiplies and xors. It is not a duplicate of any of them, and the differences are locked from the bytes: #29 folds one product with a seed addend and no key table; #43 ends in a divide-by-61 store to memory; #82 folds two streams over a variable-length loop with no keying. This window is straight-line (no branches, no loop), takes its key from a GOT-indirected table, chains exactly three unsigned 128-bit multiplies, folds both products' hi and lo halves together with the constant `0x14`, and returns a hi/lo fold of the final product. No shared primitive is claimed, and no census of mixer windows is built here.

## Heavy caveat, discharged by re-verification

This is the heaviest rule in the recent packets, so it is bound only because the rule locks exactly **and** survived independent re-verification: the window bytes were decoded with Capstone and executed by a small interpreter (deriving every operand from the decode, so it is independent of the rule's transcription) over **5,680 cases with 0 mismatches** — edge keys, edge blocks, 5,000 random cases, and single-bit/single-byte block variations. The emulator script is not committed (needs Capstone, not stdlib); 8 fixed emulator-generated vectors are recorded in `evidence.json` and replayed by the checker's `--check` path.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_keyed_multiply_xor_mixer.py --check research/work-items/foundation-keyed-multiply-xor-mixer-94/evidence.json
python3 -m unittest tests.test_foundation_keyed_multiply_xor_mixer -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x399c600 --stop-address=0x399c650 artifacts/node/94/hl-node
objdump -d --start-address=0x32aceb0 --stop-address=0x32ae31a artifacts/node/94/hl-node
objdump -d --start-address=0x32ae320 --stop-address=0x32af78a artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its ten padding bytes. The `caller.objdump.txt` file retains complete disassembly of both caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x19332c` (this window) and `0x193340` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x19332c` describes `[0x399c600, 0x399c646)`, 70 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Ten `int3` bytes follow: the next FDE starts exactly at `0x399c650` (record at `.eh_frame+0x193340`, range to `0x399c795`). The unwind-index stride is therefore 80 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window does **not** open with `endbr64` (unlike most packets): the first instruction is the rip-relative key-table pointer load.
- GNU objdump prints this window under a nearest-symbol label with a `0x160b800`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: keyed multiply-xor mixer, no branches, no calls

Complete instruction sequence, offsets relative to the FDE start:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0x00 | 48 8b 0d d9 1d dd 01 | mov 0x1dd1dd9(%rip),%rcx |
| 0x07 | 4c 8b 09 | mov (%rcx),%r9 |
| 0x0a | 48 8b 46 0c | mov 0xc(%rsi),%rax |
| 0x0e | 4c 31 c8 | xor %r9,%rax |
| 0x11 | 4c 8b 16 | mov (%rsi),%r10 |
| 0x14 | 48 8b 56 08 | mov 0x8(%rsi),%rdx |
| 0x18 | 48 33 51 08 | xor 0x8(%rcx),%rdx |
| 0x1c | 48 f7 e2 | mul %rdx |
| 0x1f | 48 89 c1 | mov %rax,%rcx |
| 0x22 | 49 89 d0 | mov %rdx,%r8 |
| 0x25 | 48 8b 46 04 | mov 0x4(%rsi),%rax |
| 0x29 | 4c 31 c8 | xor %r9,%rax |
| 0x2c | 4c 33 17 | xor (%rdi),%r10 |
| 0x2f | 49 f7 e2 | mul %r10 |
| 0x32 | 49 31 d0 | xor %rdx,%r8 |
| 0x35 | 48 31 c8 | xor %rcx,%rax |
| 0x38 | 4c 31 c0 | xor %r8,%rax |
| 0x3b | 48 83 f0 14 | xor $0x14,%rax |
| 0x3f | 49 f7 e1 | mul %r9 |
| 0x42 | 48 31 d0 | xor %rdx,%rax |
| 0x45 | c3 | ret |

Rule, derived step by step. Let `k0 = [table]`, `k1 = [table+8]`, where `table` is the pointer loaded from the GOT slot at `0x576e3e0`:

- First product: `A = (qword[rsi+12] ^ k0) * (qword[rsi+8] ^ k1)`, unsigned 64x64→128, giving `(lo1, hi1)`; `lo1` is saved in rcx, `hi1` in r8.
- Second product: `B = (qword[rsi+4] ^ k0) * (qword[rsi] ^ [rdi])`, unsigned 64x64→128, giving `(lo2, hi2)`; `hi2` is folded into r8, then `lo1` and the folded highs are xored into rax.
- Fold: `T = lo1 ^ lo2 ^ hi1 ^ hi2 ^ 0x14`.
- Final: `C = T * k0`, unsigned 64x64→128, giving `(lo3, hi3)`; the return value is `lo3 ^ hi3`.

No call opcode appears inside the window, and there are no branches at all. No field is written, and no other register state is claimed. The `0x14` fold survives even when both products are zero (the unit-key edge in the checker: zero block, `k0 = 1`, `k1 = 0` returns `0x14`); when `k0 = 0` the result is always 0.

### Incoming calls: two direct sites in two caller FDEs

A byte-pattern scan over the full `.text` section (70,370,352 bytes) for `e8` sites whose rel32 lands on the window start finds exactly two sites, each confirmed as an instruction start by linear disassembly from its caller FDE start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan.

| Call site | Call bytes | Caller FDE | Setup immediately before the call |
| --- | --- | --- | --- |
| 0x32ad5f3 | e8 08 f0 6e 00 | 0x32aceb0..0x32ae31a | lea 0x20(%r13),%rdi; mov %rsi,0x8(%rsp) |
| 0x32aea63 | e8 98 db 6e 00 | 0x32ae320..0x32af78a | lea 0x20(%r13),%rdi; mov %rsi,0x8(%rsp) |

Both callers share the same setup sequence; caller purposes are not claimed.

### Data edge: no naming relocation; one GOT reference

No `R_X86_64_RELATIVE` or other relocation record in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The key-table pointer is a rip-relative reference into `.got` (slot `0x576e3e0`), not a naming relocation, and it does not identify the window's provenance.

## Inferences

- The "keyed multiply-xor mixer" label is an inference from the observed rule: two keyed unsigned products folded with a constant through a third keyed multiply. It is kept separate from the rule itself.
- The key table is plausibly a per-instance or global mixing key, but its owner and contents are runtime values and are not claimed.
- The two callers plausibly feed the same 20-byte input shape, but their purposes are unknown and not claimed.

## Unknowns

- What the mixed value means, and what reads the result.
- The key table's contents, owner, and lifetime (runtime-filled).
- Whether the window is also reached via indirect calls or tail jumps (out of scope for the direct-e8 scan).
- The source-level function, type, and component ownership of this window.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the GOT reference does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
