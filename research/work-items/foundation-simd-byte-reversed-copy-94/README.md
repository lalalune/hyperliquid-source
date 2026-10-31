# foundation-simd-byte-reversed-copy-94: what does the SIMD struct-copy window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 132-byte FDE window with twelve padding bytes, the SIMD struct-copy rule with its exact fields, the exact incoming-call scan result (zero direct sites), and the one-slot relocation result.
- Excluded: what the fields mean, what record type this copies, any wider copy-component claim, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a straight-line copy that writes a verbatim 16-byte + 4-byte header and then two byte-reversed 16-byte fields, each reversal done by the same SSE unpack/shuffle/pack sequence. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x3818d40`, no open pull request title mentions it or SIMD/byte-reversed copy, and its bytes overlap nothing in packets #1–#121.

## Scout note

The round-24 scout note listed this window (ranked #1, the only ranked item this round) with FDE `[0x3818d40, 0x3818dc4)`, 132 bytes, 12 padding bytes, 2 preceding gap bytes, zero direct callers, one naming relocation slot (`0x5775570`), and a twin guard of 12/127. Every element verified exactly — except the scout's frame-offset notation, which the bytes correct (see below).

## Scout correction: the frame offsets are unwind-index values, not section offsets

The scout note cites the window's frame record as `.eh_frame+0xe66c24`. That value is the unwind index's `fde_va` column, not the record's offset inside the `.eh_frame` section. The actual section offsets, verified from the raw records with GNU `--dwarf=frames`, are: previous FDE at `0x1856f8` (pc `0x3818cf0..0x3818d3e`), this window's FDE at `0x18570c` (pc `0x3818d40..0x3818dc4`), next FDE at `0x185720` (pc `0x3818dd0..0x3818e68`), plus the shared CIE at offset `0`. The checker locks these section offsets, not the index values. No other scout element needed correction.

## Idiom disclosure, stated head-on

The SIMD unpack/shuffle/pack idiom recurs broadly: 92 FDEs of 400 bytes or fewer contain `punpcklbw` + `packuswb`, and the `pshufd 0x4e` byte pattern (`66 0f 70 d2 4e`) has 193 hits in all of `.text`. But NO body matches this window: the maximum body-match among the 92-FDE SIMD family is 13/132 (vs `0x135c8e0`, 140 bytes), and the same maximum holds among the 87 FDEs containing the full reversal sequence (`punpcklbw` + `punpckhbw` + `pshufd 0x4e` + `pshuflw 0x1b` + `pshufhw 0x1b` + `packuswb`). The idiom's recurrence elsewhere does not make this window a population member. The twin guard below was re-run by this builder, not taken on scout trust.

## Sibling-pattern scan, stated head-on (required since round 24)

The claimed-body guard alone cannot catch unclaimed siblings: round 24 killed a 104-byte candidate (`0x275fa60`) when a sibling-pattern scan found two adjacent 104-byte FDEs carrying the identical rule, one an exact 104/104 twin. So this builder ran the sibling scan for this window explicitly:

- Immediate neighbours differ in kind: the previous FDE (`0x3818cf0`, 78 bytes) is a tail-jump dispatch (byte test + three `jmp` exits, no SIMD, no stores of this shape), and the next FDE (`0x3818dd0`, 152 bytes) is a calls function (two `call` sites, `movabs` magic, `movups` stores at different offsets). Neither shares the verbatim-header + two-reversed-fields layout.
- Across all FDEs of 400 bytes or fewer containing the full reversal sequence (87 FDEs), the maximum body-match against this window is 13/132 (`0x135c8e0`, 140 bytes) — the same figure as the SIMD-family scan. No adjacent or nearby FDE carries this window's rule shape.
- Conclusion: no sibling twin exists for this window by either the claimed-body guard or the sibling-pattern scan. The scan result is a positive finding (no twin), not an absence of checking.

## Distinction from packet #113, stated head-on

Packet #113 (`0x5632d90`, byte-swapped reversed 4-qword copy) also reverses bytes, but by a different mechanism and layout: `bswap` on four qwords in reverse order, versus this window's SSE word-shuffle reversal of two 16-byte fields behind a verbatim 16-byte + 4-byte header. The byte-compare between the two bodies is 2/43 — not a twin by any reading. The two packets are distinct windows with distinct rules.

## Provenance, stated plainly

Round-24 GENERAL slice, big bucket 375+ — not any peer lane. The round-24 peer lanes (#1050 liquidate path, #1051 aligned quote yield) yielded zero rankable items and are not claimed here.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_simd_byte_reversed_copy.py --check research/work-items/foundation-simd-byte-reversed-copy-94/evidence.json
python3 -m unittest tests.test_foundation_simd_byte_reversed_copy -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x3818d40 --stop-address=0x3818dd0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its twelve padding bytes. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x1856f8` (previous FDE), `0x18570c` (this window), and `0x185720` (next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x18570c` describes `[0x3818d40, 0x3818dc4)`, 132 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Twelve `int3` bytes follow: the next FDE starts exactly at `0x3818dd0` (record at `.eh_frame+0x185720`, range to `0x3818e68`). The unwind-index stride is therefore 144 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- Two `int3` bytes precede the window (the previous FDE ends at `0x3818d3e`); that gap is padding, not code, and the checker locks it as a boundary.
- The window opens with `mov %rdi,%rax`, NOT `endbr64` — the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x3818d40`.

- Offset `0x00`: `mov %rdi,%rax` — save the out pointer (also the incidental return value).
- Offset `0x03`: `mov 0x30(%rsi),%ecx` — header dword load.
- Offset `0x06`: `mov %ecx,0x10(%rdi)` — header dword store.
- Offset `0x09`: `movups 0x20(%rsi),%xmm0` — verbatim 16-byte load.
- Offset `0x0d`: `movups %xmm0,(%rdi)` — verbatim 16-byte store.
- Offset `0x10`: `movdqu 0x10(%rsi),%xmm0` — first reversed-field load.
- Offset `0x15`: `pxor %xmm1,%xmm1` — zero register for the unpacks.
- Offset `0x19`: `movdqa %xmm0,%xmm2` — first low-half copy.
- Offset `0x1d`: `punpcklbw %xmm1,%xmm2` — widen low bytes to words.
- Offset `0x21`: `pshufd $0x4e,%xmm2,%xmm2` — swap 32-bit lanes.
- Offset `0x26`: `pshuflw $0x1b,%xmm2,%xmm2` — reverse words in the low half.
- Offset `0x2b`: `pshufhw $0x1b,%xmm2,%xmm2` — reverse words in the high half.
- Offset `0x30`: `punpckhbw %xmm1,%xmm0` — widen high bytes to words.
- Offset `0x34`: `pshufd $0x4e,%xmm0,%xmm0` — swap 32-bit lanes.
- Offset `0x39`: `pshuflw $0x1b,%xmm0,%xmm0` — reverse words in the low half.
- Offset `0x3e`: `pshufhw $0x1b,%xmm0,%xmm0` — reverse words in the high half.
- Offset `0x43`: `packuswb %xmm2,%xmm0` — pack words back to bytes.
- Offset `0x47`: `movdqu %xmm0,0x14(%rdi)` — first reversed-field store.
- Offset `0x4c`: `movdqu (%rsi),%xmm0` — second reversed-field load.
- Offset `0x50`: `movdqa %xmm0,%xmm2` — second low-half copy.
- Offset `0x54`: `punpcklbw %xmm1,%xmm2` — widen low bytes to words.
- Offset `0x58`: `pshufd $0x4e,%xmm2,%xmm2` — swap 32-bit lanes.
- Offset `0x5d`: `pshuflw $0x1b,%xmm2,%xmm2` — reverse words in the low half.
- Offset `0x62`: `pshufhw $0x1b,%xmm2,%xmm2` — reverse words in the high half.
- Offset `0x67`: `punpckhbw %xmm1,%xmm0` — widen high bytes to words.
- Offset `0x6b`: `pshufd $0x4e,%xmm0,%xmm0` — swap 32-bit lanes.
- Offset `0x70`: `pshuflw $0x1b,%xmm0,%xmm0` — reverse words in the low half.
- Offset `0x75`: `pshufhw $0x1b,%xmm0,%xmm0` — reverse words in the high half.
- Offset `0x7a`: `packuswb %xmm2,%xmm0` — pack words back to bytes.
- Offset `0x7e`: `movdqu %xmm0,0x24(%rdi)` — second reversed-field store.
- Offset `0x83`: `ret` — single return.

The two reversal blocks are byte-identical in structure (same opcodes at the same relative offsets within each block); only the load/store displacements differ. The reversal claim is verified by the word-level model in the checker: widened words are lane-swapped, word-reversed per 64-bit half, and packed back, which is exactly a byte reversal — confirmed on bytes 0..15, a marker pattern, and all zeros.

### Data edges

- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds exactly zero direct `e8` sites — explicitly not a complete xref census. No caller file exists for this packet.
- Relocations: exactly one `R_X86_64_RELATIVE` record names this window as addend — slot `0x5775570` (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries), reported as a slot list only, no meaning claimed.
- Twin guard, re-run by this builder: full claimed-body byte-compare over 532 FDE bodies (packets #1–#121 claimed list plus known do-not-build windows; the unwindless packet #115 body compared separately) gives a top match of only 12/127 vs `0x4c69260` (the round-22 dispatch third arm) — not a twin. Byte-compare vs packet #113's body is 2/43 — not a twin. The nearest claimed window is far; the byte-compare is the operative guard, not distance.

## Inferences

- The "SIMD struct copy with two byte-reversed 16-byte fields" label is an inference from the observed rule: a verbatim header plus two reversed fields, total out size `0x34`. The fields' semantics, the record's type, and the copy's purpose are not inferred.
- The two reversal blocks' structural identity suggests one repeated operation applied twice, but no shared-helper or inlining claim is made — the blocks are inline in this window either way.
- The window's lack of `endbr64` and its zero direct callers are consistent with a private helper reached indirectly or by a path the byte-pattern scan cannot see, but that is a consistency note, not a provenance claim.

## Unknowns

- What the source record and output record are, and what any field means.
- Whether the single relocation slot relates the window to a table, a vtable, or something else — the slot is a list entry, not an identification.
- How the window is reached, given zero direct call sites in the byte-pattern scan.
- Whether other windows elsewhere perform the same copy with different field offsets — the sibling scan above covers the reversal sequence, not every possible copy layout.

## Limits

- The byte-pattern scan is not a complete xref census, and the relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
