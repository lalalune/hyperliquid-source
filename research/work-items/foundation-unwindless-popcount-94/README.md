# foundation-unwindless-popcount-94: what does the unwindless SWAR popcount64 window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 98-byte unwindless window with its 12 leading and 14 trailing int3 bytes, the SWAR popcount64 rule with its exact masks and shifts, the unwindless proof (no FDE covers the window, bracketing FDEs locked), the exact incoming-call scan result (25 direct sites, each boundary-confirmed in one of 6 caller FDEs), and the zero naming-relocation-slot result.
- Excluded: what the counted value represents, what the callers do with the count, any wider popcount family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a shift-mask-add population count with fixed masks, fixed shifts, and a fixed 32-bit fold, with no call inside and a single return. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5660010`, no open pull request title mentions it or unwindless-popcount, and its bytes overlap nothing in packets #1–#114.

## Scout note — with one correction

The round-19 scout note listed this window (ranked #3) as unwindless, 97 bytes `[0x5660010, 0x5660071)`, 12 leading int3 bytes, 14 trailing int3 bytes, zero branches, zero calls inside, 25 direct callers (first 7 boundary-confirmed), 0 naming slots, and nearest claimed window `0x565eea0` `0x1170` away. Every element verified exactly **except the byte count**: the window is **98 bytes `[0x5660010, 0x5660072)`**, not 97, because the `ret` at `0x5660071` is part of the window — the scout's end excluded the ret byte. The int3 runs (12 leading, 14 trailing) and the 124-byte gap total confirm the correction: 12 + 98 + 14 = 124 = `0x5660080` − `0x5660004`. The full caller check is also stronger than scouted: all 25 sites (not just the first 7) are boundary-confirmed inside their caller FDEs.

## Caveats, stated head-on

- **Shared helper, disclosed not hidden.** Twenty-five direct callers make this a shared helper. Compare explicitly with the excluded shared-helper precedent `0x4f955d0` (162 direct sites, excluded from ranked and backup in round 16): this window is a different scale (25 vs 162 sites), but the shared-helper character is stated here, not buried. Nothing here claims this window is a private single-use helper.
- **NOT a twin of the nearest claimed packet.** The nearest claimed window `0x565eea0` is `0x1170` away, and this window was byte-compared against it directly: **0/26** bytes identical over the 26-byte overlap, with a different size (98 vs 26) and a different rule (SWAR popcount64 vs imul/sub store: rax=rdx; rdx*=[rsi]; [rdi]-=rdx; [rdi+8]=rax). It is not that window, not a variant of it, and nothing here re-claims it.
- **Unwindless-lane distinction.** The nearest peer PR in this neighbourhood (live #981, the unwindless-boundary PR) covers a code-filled gap ending at `0x5631f00`. This window sits at the opposite end of `.text` (`0x5660010`, near the section end `0x56600b0`), in a different gap, with a different rule. It IS an unwindless function in that lane's character, but it is NOT one of the peer's two gap candidates: different location, different gap, different rule. Nothing here re-claims, re-states, or grades the peer's gap work.
- **Symbol-label disclaimer.** GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it. In particular, no stdlib or private provenance is claimed either way: the compiler-intrinsic shape of the SWAR sequence is an observation about the bytes, not a claim about which compiler or library produced them.
- **Caller scale, stated plainly.** Twenty-five direct callers is a retained fact (all six caller FDEs are kept in `caller.objdump.txt`), not a population claim. The byte-pattern scan is not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope.
- **Thinness, stated plainly.** This is a single-purpose window: one input, one count, one return. What it is not is ambiguous — the masks, the shifts, the fold order, and the 32-bit truncation points are all fixed by the bytes with no room for an alternate reading. The packet claims exactly that one rule and nothing more.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_unwindless_popcount.py --check research/work-items/foundation-unwindless-popcount-94/evidence.json
python3 -m unittest tests.test_foundation_unwindless_popcount -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5660004 --stop-address=0x5660080 artifacts/node/94/hl-node
objdump -d --start-address=0x4f9eb90 --stop-address=0x4f9eba5 artifacts/node/94/hl-node
objdump -d --start-address=0x4fb3040 --stop-address=0x4fb3ff9 artifacts/node/94/hl-node
objdump -d --start-address=0x5363490 --stop-address=0x5363ba2 artifacts/node/94/hl-node
objdump -d --start-address=0x54cd010 --stop-address=0x54cd781 artifacts/node/94/hl-node
objdump -d --start-address=0x54cd790 --stop-address=0x54cde02 artifacts/node/94/hl-node
objdump -d --start-address=0x5525500 --stop-address=0x55261af artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly from the previous FDE's end (`0x5660004`) to the next FDE's start (`0x5660080`): the 12 leading int3 bytes, the 98-byte window, and the 14 trailing int3 bytes. The `caller.objdump.txt` file retains complete disassembly of all six caller FDEs. The `frames.txt` file retains excerpts selecting the shared CIE at offset `0`, the bracketing FDEs at `.eh_frame` section offsets `0x2dc6cc` (PREV) and `0x2dc6e4` (NEXT), and the six caller FDEs at `0x28ac50`, `0x6231ac`, `0x2b2ba0`, `0x2c0638`, `0x2c06a0`, and `0x2c9ae0`. Note the `0x4fb3040` caller FDE uses the CIE at offset `0x6205d0`, not CIE0; the checker locks its raw record and PC/range regardless. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, unwindless gap, and padding

- No FDE record covers `[0x5660010, 0x5660072)`. GNU's independent frame dump agrees: the previous FDE ends at `0x5660004` (record at `.eh_frame+0x2dc6cc`, range `0x565ff80..0x5660004`), the next FDE starts at `0x5660080` (record at `.eh_frame+0x2dc6e4`, range `0x5660080..0x5660092`), and no FDE record starts inside the gap `[0x5660004, 0x5660080)`. The checker additionally walks every `.eh_frame` record and proves no FDE pc/range contains `0x5660010`.
- The gap is 124 bytes: 12 `int3` bytes (`0x5660004..0x5660010`), the 98-byte window, and 14 `int3` bytes (`0x5660072..0x5660080`). The unwind-index stride is therefore not an FDE extent here at all — there is no FDE extent to confuse with the stride — and the checker locks the body and both int3 runs separately.
- The window opens with `mov %rdi,%rax`, not `endbr64` — the retained entry shape, not an assumption about how the window is reached.
- The next FDE (`0x5660080..0x5660092`) is the `__cxa_atexit` stub (endbr64, mov, xor, jmp to `__cxa_atexit@plt`), retained only as the upper bracket; nothing about the stub's purpose is claimed beyond its bytes.
- `.text` ends at `0x56600b0`, so this window ends 62 bytes before the section end (14 trailing int3 bytes, the 18-byte stub FDE, 14 more int3 bytes, and a final 16-byte FDE fill the rest). That position is consistent with an unwindless tail function, but position alone is not the claim — the missing FDE coverage is.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the window start `0x5660010`. `rdi` holds the input throughout the 64-bit stages; `rax` holds the running value; the fold stages use 32-bit registers, so they truncate to 32 bits.

- Offset `0x00`: `mov %rdi,%rax` — input copy.
- Offset `0x03`: `shr $0x1,%rax` — halved input.
- Offset `0x06`: `movabs $0x5555555555555555,%rcx` — alternating-bit mask.
- Offset `0x10`: `and %rax,%rcx` — masked halved input.
- Offset `0x13`: `sub %rcx,%rdi` — pairwise bit sums in 2-bit fields.
- Offset `0x16`: `mov %rdi,%rax` — pairwise sums copy.
- Offset `0x19`: `shr $0x2,%rax` — quartered sums.
- Offset `0x1d`: `movabs $0x3333333333333333,%rcx` — 2-bit-field mask.
- Offset `0x27`: `and %rcx,%rax` — masked quartered sums.
- Offset `0x2a`: `and %rdi,%rcx` — masked pairwise sums.
- Offset `0x2d`: `add %rax,%rcx` — bit sums in 4-bit fields.
- Offset `0x30`: `mov %rcx,%rax` — nibble sums copy.
- Offset `0x33`: `shr $0x4,%rax` — shifted nibble sums.
- Offset `0x37`: `add %rcx,%rax` — paired nibble sums.
- Offset `0x3a`: `movabs $0xf0f0f0f0f0f0f0f,%rcx` — byte-field mask.
- Offset `0x44`: `and %rax,%rcx` — per-byte bit sums.
- Offset `0x47`: `mov %rcx,%rax` — per-byte sums copy.
- Offset `0x4a`: `shr $0x20,%rax` — high half shifted down.
- Offset `0x4e`: `add %ecx,%eax` — 32-bit fold of the two halves.
- Offset `0x50`: `mov %eax,%ecx` — folded copy.
- Offset `0x52`: `shr $0x10,%ecx` — high 16 bits shifted down.
- Offset `0x55`: `add %eax,%ecx` — 32-bit fold of the halves.
- Offset `0x57`: `mov %ecx,%eax` — folded copy.
- Offset `0x59`: `shr $0x8,%eax` — high byte shifted down.
- Offset `0x5c`: `add %ecx,%eax` — 32-bit fold of the bytes.
- Offset `0x5e`: `and $0x7f,%eax` — result masked to 7 bits (the maximum count is 64, so bit 6 is the highest that can be set; the mask itself is locked as a literal).
- Offset `0x61`: `ret` — single return on the only path.

### Inferences

- The window computes the population count (number of set bits) of its 64-bit input. This is an inference from the instruction sequence, kept separate from the observed rule: the sequence is the textbook shift-mask-add reduction, and the retained edges (0 → 0, 1 → 1, all-ones → 64, alternating patterns → 32) all agree with a bit count and with no other simple rule the bytes suggest.
- The 32-bit fold is exact for this purpose: after the byte-mask stage, each byte holds a value 0..8, so the 64-bit sum of the eight bytes is at most 64 and fits in 32 bits with room to spare; the truncation points cannot change the result for any input, but they are locked as literals anyway.
- The `& 0x7f` mask is consistent with a count result (0..64 needs 7 bits) but is not, by itself, proof of the rule — the full reduction above is.

### Unknowns

- What value is counted, what the 25 callers do with the count, and whether any caller depends on the count's exact value or only on zero/nonzero.
- Whether this window corresponds to a compiler intrinsic, a standard-library routine, or private code. No source-level provenance is claimed either way.
- Whether indirect calls, tail jumps, or PLT references also reach this window; the retained scan covers direct `e8` sites only.
- Why this window has no FDE while its neighbours do (stripped tail, hand-written assembly, or linker treatment are all unclaimed possibilities).

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere. The "unwindless SWAR popcount64" label is an inference, kept separate from the observed rule.
- The byte-pattern scan is not a complete xref census, and the absence of relocation slots does not identify the window's provenance.
- The `.eh_frame` walk in the checker assumes the pcrel sdata4 initial-location encoding recorded in the binary's CIEs; it is validated against the locked bracketing and caller records, not assumed for the whole table without that anchor.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
