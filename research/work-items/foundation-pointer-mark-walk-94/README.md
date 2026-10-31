# foundation-pointer-mark-walk-94: what does the pointer-mark walk window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 146-byte FDE window with fourteen padding bytes, the pointer-mark walk rule with its exact count formula, two-array entry selection, chain-walk termination conditions, and mark-value derivation, the exact incoming-call scan result (four direct sites, each boundary-confirmed), and the zero-relocation data edge.
- Excluded: what the walked fields mean, what the mark value represents, what reads the marked nodes, any wider walk family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a walk that, per entry, follows a chain and stamps a mark value into each node whose stamp field still holds a mask sentinel. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x50e69f0`, no open pull request title mentions it or pointer-mark-walk, and its bytes overlap nothing in packets #1–#87.

Heaviness is stated head-on: this is a heavy backup item (round-13 backup B2) — a 146-byte window with an outer entry loop, an inner chain walk, two entry arrays, and three termination conditions, component-entangled through the 0x8f8/0xcc8/0x10 fields. It is bound only because the rule locks exactly from its own bytes and survived independent re-verification (a Capstone-decoded interpreter over 3,070 synthetic layouts with 0 mismatches; see below), not because it is small.

## Scout note

The round-13 scout note listed this window (backup B2) with FDE `[0x50e69f0, 0x50e6a82)`, 146 bytes, 14 padding bytes to next FDE `0x50e6a90`, a count formula `[rsi] + ([rsi+0x58] - [rsi+0x50]) / 8`, a per-entry `[entry+0x8f8]` chain marking `[node+0xcc8]`, and a warning that the exact walk rule needs deeper verification before any claim locks. Every scouted number verified exactly (FDE range, 146-byte body, 14 padding bytes, count formula shape).

Two material corrections and several additions came out of the deeper verification, all stated here rather than buried:

- **Direction of the mask test (correction).** The scout summary reads as if the walk marks nodes *until* it reaches a node whose `[node+0xcc8]` already equals the mask. The bytes show the reverse: a node is marked **only when** its `[node+0xcc8]` already equals the mask `0x00ffffffffffffff`; reaching a node whose field differs from the mask **stops** the walk for that entry, leaving that node untouched. The mask is the "still unmarked" sentinel, not the termination signal.
- **Termination structure (correction/precision).** The walk does not end only at a self-referential head. There are three distinct stops: the initial head check (`[head] == head` writes nothing), the non-mask stop above, and the post-advance check (`cur == head` after marking). The scout's single "self-referential head or mask" phrasing collapses the first and third stops and misstates the second.
- **Additions the scout note did not state.** The outer loop's entry selection (first 8 entries from the `[rsi+0x48]` array, the rest from the `[rsi+0x50]` array, via the `r8 > 7` gate and the `r9 = begin - 0x40` cursor); the mark value derivation (`[[rdi+0x68]+0x108]`, computed once); the `N == 0` early return; the 9-byte `nopw` and 3-byte `nopl` inside the FDE (alignment bytes, targeted by no branch); the four direct callers (the scout note gave no caller count for this window); and the zero-relocation data edge. The nearest claimed window is two-field byte gate `0x51384e0` (packet #45), `0x51af0` away — verified against all 87 prior packet branches' retained evidence, not estimated.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_pointer_mark_walk.py --check research/work-items/foundation-pointer-mark-walk-94/evidence.json
python3 -m unittest tests.test_foundation_pointer_mark_walk -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x50e69f0 --stop-address=0x50e6a90 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its fourteen padding bytes. The `caller.objdump.txt` file retains complete disassembly of all four caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x297df0` (this window) and `0x297e04` (the next FDE), the shared CIE at offset `0`, the caller CIE at `0x6205d0`, and the caller FDEs at `0x629b64`, `0x630268`, `0x6302c8`, `0x630340`. The checker locks these raw FDE records and their CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x297df0` describes `[0x50e69f0, 0x50e6a82)`, 146 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Fourteen `int3` bytes follow: the next FDE starts exactly at `0x50e6a90` (record at `.eh_frame+0x297e04`, range to `0x50e6ab4`). The unwind-index stride is therefore 160 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the usual entry marker.
- GNU objdump prints this window under a nearest-symbol label with a `0x13ebf0`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: pointer-mark walk, no calls, seven branches

Complete instruction sequence, offsets relative to the FDE start:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0x00 | f3 0f 1e fa | endbr64 |
| 0x04 | 48 8b 47 68 | mov 0x68(%rdi),%rax |
| 0x08 | 49 89 f3 | mov %rsi,%r11 |
| 0x0b | 48 8b b8 08 01 00 00 | mov 0x108(%rax),%rdi |
| 0x12 | 4c 8b 4e 50 | mov 0x50(%rsi),%r9 |
| 0x16 | 4c 8b 56 58 | mov 0x58(%rsi),%r10 |
| 0x1a | 4d 29 ca | sub %r9,%r10 |
| 0x1d | 49 c1 fa 03 | sar $0x3,%r10 |
| 0x21 | 4c 03 16 | add (%rsi),%r10 |
| 0x24 | 74 6b | je 0x50e6a81 |
| 0x26 | 49 83 e9 40 | sub $0x40,%r9 |
| 0x2a | 45 31 c0 | xor %r8d,%r8d |
| 0x2d | 48 be ff ff ff ff ff ff ff 00 | movabs $0xffffffffffffff,%rsi |
| 0x37 | 66 0f 1f 84 00 00 00 00 00 | nopw 0x0(%rax,%rax,1) |
| 0x40 | 4c 89 c8 | mov %r9,%rax |
| 0x43 | 49 83 f8 07 | cmp $0x7,%r8 |
| 0x47 | 77 08 | ja 0x50e6a41 |
| 0x49 | 49 8b 43 48 | mov 0x48(%r11),%rax |
| 0x4d | 4a 8d 04 c0 | lea (%rax,%r8,8),%rax |
| 0x51 | 48 8b 00 | mov (%rax),%rax |
| 0x54 | 48 8b 88 f8 08 00 00 | mov 0x8f8(%rax),%rcx |
| 0x5b | 48 8b 01 | mov (%rcx),%rax |
| 0x5e | 48 39 c8 | cmp %rcx,%rax |
| 0x61 | 75 14 | jne 0x50e6a67 |
| 0x63 | eb 1f | jmp 0x50e6a74 |
| 0x65 | 0f 1f 00 | nopl (%rax) |
| 0x68 | 48 8b 00 | mov (%rax),%rax |
| 0x6b | 48 89 ba c8 0c 00 00 | mov %rdi,0xcc8(%rdx) |
| 0x72 | 48 39 c8 | cmp %rcx,%rax |
| 0x75 | 74 0d | je 0x50e6a74 |
| 0x77 | 48 8b 50 10 | mov 0x10(%rax),%rdx |
| 0x7b | 48 39 b2 c8 0c 00 00 | cmp %rsi,0xcc8(%rdx) |
| 0x82 | 74 e4 | je 0x50e6a58 |
| 0x84 | 49 83 c0 01 | add $0x1,%r8 |
| 0x88 | 49 83 c1 08 | add $0x8,%r9 |
| 0x8c | 4d 39 c2 | cmp %r8,%r10 |
| 0x8f | 75 af | jne 0x50e6a30 |
| 0x91 | c3 | ret |

Rule, derived step by step:

- **Mark value, computed once.** `rdi` becomes `[[rdi+0x68]+0x108]` — a two-hop load from the original first argument. Nothing inside the loop changes `rdi`, so every mark write stores this same value. The original `rdi` is otherwise unused.
- **Count.** `N = [rsi] + (([rsi+0x58] - [rsi+0x50]) >> 3)`, with an arithmetic shift. If `N == 0`, the `je` at offset `0x24` returns immediately with no writes. Otherwise the outer loop runs while `i != N`, `i` starting at 0 and incrementing by 1 per entry. Note: the loop condition is exactly `i != N`; for negative `N` the bytes give no exit except counter wraparound, and no negative-`N` behavior is claimed — valid-range inputs give `N >= 0`.
- **Entry selection (two arrays).** `r9` starts at `[rsi+0x50] - 0x40` and grows by 8 per entry. For entry index `i <= 7` (unsigned gate at offset `0x47`), the slot address is `[rsi+0x48] + 8*i`; for `i >= 8` it is `r9`, i.e. `[rsi+0x50] + 8*(i-8)`. The entry pointer is then loaded from that slot. Arithmetic observation, kept as inference: with `[rsi] == 8`, the second-array consumption exactly fills `[begin, end)`; other `[rsi]` values shift that alignment, and no field meaning is claimed for `[rsi]`.
- **Inner walk, per entry.** `rcx = [entry+0x8f8]` (the head pointer); `cur = [rcx]`. If `cur == rcx`, the entry is done with no writes (empty chain). Otherwise repeat: `node = [cur+0x10]`; if `[node+0xcc8] != 0x00ffffffffffffff`, the entry is done and that node is left untouched; else `cur = [cur]`, then `[node+0xcc8] = mark`, and if the new `cur == rcx`, the entry is done. The mark is written to the node derived from the *previous* `cur`, after advancing — the order in the bytes is advance-then-store, and the checker locks it.
- **No return contract.** `ret` leaves `rax` holding the last walk value, which varies by path; no return value is claimed.
- **Alignment bytes inside the FDE.** The 9-byte `nopw` at offset `0x37` sits before the loop head (targeted by the loop back-edge at offset `0x8f`, which lands at `0x40`, not on the `nopw`), and the 3-byte `nopl` at offset `0x65` sits between the `jmp` and the mark step (reached only via the `je` at offset `0x82`). Both are locked as bytes, not behavior.

### Incoming calls: four direct sites, each boundary-confirmed

A byte-pattern scan over the full `.text` section (70,370,352 bytes) for `e8` sites whose rel32 lands on the window start finds exactly four sites, each confirmed as an instruction start by linear disassembly from its caller FDE start (not merely by the byte pattern):

| Call site | Call bytes | Caller FDE | Setup immediately before the call |
| --- | --- | --- | --- |
| 0x5041978 | e8 73 50 0a 00 | 0x50409d0..0x5041eed | lea 0x1b0(%rsp),%r12 |
| 0x50ec3cb | e8 20 a6 ff ff | 0x50ebfb0..0x50ec9d7 | lea -0x140(%rbp),%r15 |
| 0x50ecf60 | e8 8b 9a ff ff | 0x50eca90..0x50ed403 | lea 0x140(%rsp),%r15 |
| 0x50edac8 | e8 23 8f ff ff | 0x50ed4b0..0x50edda0 | mov %r14,%rsi |

This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. No caller purpose is claimed.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation does not identify the window's provenance.

### Independent re-verification: Capstone-decoded interpreter sweep

Because the scout flagged this window as heavy and entangled, the decoded rule was re-verified independently of its transcription: the window bytes were decoded with Capstone and executed by a small interpreter (deriving every operand from the decode — mnemonics, registers, memory operands, and branch targets — so it is independent of the rule's transcription) over **3,070 synthetic layouts with 0 mismatches**. The sweep covered count sweeps (`s0` in {0, 1, 3, 8} × second-array counts in {0, 1, 5, 8, 12}), randomized entry/chain shapes (empty heads, mask/non-mask chains, multi-link chains), the entry-7/entry-8 array boundary, and 50 hand-built self-loop-link cases. Final memory states (every mark field) matched the rule model exactly in all cases. The check was non-vacuous: a 13-entry mixed-shape case changed exactly 15 mark fields, all to the mark value, matching the mask-prefix lengths of its chains. The emulator script is not committed (it needs Capstone, not stdlib); the committed checker replays the rule edges on synthetic layouts with the standard library only.

## Inferences

- The "pointer-mark walk" label, the "table struct" reading of `rsi`, the "head/link/node" reading of the chain, and the "still unmarked" reading of the mask sentinel are inferences, kept separate from the observed rule above.
- The `[rsi] == 8` alignment observation (second-array consumption exactly filling `[begin, end)`) is arithmetic, not a claim about valid inputs or field meanings.
- The four callers plausibly invoke the same walk for different tables, but no caller purpose, call-site role, or shared-primitive claim is made.

## Unknowns

- What the `rsi` fields mean (`+0x00`, `+0x48`, `+0x50`, `+0x58`), what the `+0x8f8` head pointer, `+0x10` link field, and `+0xcc8` stamp field belong to, and what the mark value represents.
- What reads the marked nodes, whether marking is idempotent in the callers' use, and what happens for inputs outside the valid range (negative `N`, unaligned array bounds, non-mask first nodes on every entry).
- Which source-level function, if any, this window corresponds to; the nearest-symbol label is stripped-binary arithmetic, not an identity.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
