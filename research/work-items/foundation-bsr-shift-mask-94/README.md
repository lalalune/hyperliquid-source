# foundation-bsr-shift-mask-94: what does the bsr-derived shift-mask window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 66-byte FDE window with 14 padding bytes, the bsr-derived shift-mask rule with its exact constants, the exact incoming-call scan result (two direct sites in two caller FDEs), and the zero-naming-relocation scan result.
- Excluded: what the input value means, what the masked field represents, any wider bsr family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a single-input computation that derives a bit index with bsr, extracts a two-bit field with a shift-and-mask, and returns the field plus a linear term in the clamped index. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x54b4390`, no open pull request title mentions it or bsr-shift-mask, and its bytes overlap nothing in packets #1–#107.

## Scout note

The round-16 scout note listed this window (backup B2, the second backup after ranked #1–#4 and backup B1) with FDE `[0x54b4390, 0x54b43d2)`, 66 bytes, 14 padding bytes, two direct callers (both boundary-confirmed), no naming relocation, and nearest claimed window bit-writer drain `0x5494050` (packet #84) `0x20340` away. Every scouted element verified exactly, with one refinement to the scout's result formula, stated head-on below: the scout wrote the result as `masked + 4*bsr − 0x17`, but the retained bytes clamp the index in the final term too (`cmovb` at offset `0x39` replaces a bsr below 6 with 6), so the locked rule is `masked + 4*max(bsr, 6) − 0x17`. The two formulas agree whenever bsr ≥ 6 and differ for inputs with bsr < 6 (that is, rdi ≤ 32); the edge checks below pin the clamped behavior (rdi = 32 gives 2, not 1 + 20 − 23 = −2 mod 2^32).

## Caller caveat

Two direct `e8` call sites reach this window, each confirmed as an instruction start by linear disassembly from its caller FDE start (retained in `caller.objdump.txt`): `0x54c6268` (FDE `0x54c5620..0x54c7547`) and `0x54c85d5` (FDE `0x54c7550..0x54c8ca5`). The byte-pattern scan is explicitly not a complete xref census, and no caller purpose is claimed.

## Bsr-family caveat, stated head-on

This window sits in the bit-index family with packet #49 (bsr clamp ladder) and packet #95 (divide-then-log2 bucket), and the three rules are distinct in mechanism, inputs, and outputs — no shared primitive is claimed:

- Packet #49 takes four inputs and combines three separate bsr values (of `rsi-1`, `rdx`, and `rsi`) into a hi/lo pair, then runs a min/max clamp chain over a value to the [5, 12] band. This window takes one input, computes a single bsr (of `2*rdi-1`), and returns a masked field plus a linear term — no clamp chain, no second or third bsr.
- Packet #95 takes two inputs, divides the first by the second (unsigned `div`, which traps on a zero divisor), then computes `min(floor(log2(quotient)), 6)` with five shift tests plus an arithmetic cap. This window has no division, no quotient, and no bucket cap: its output is the extracted two-bit field plus `4*clamped − 23`, not a bucket index.
- What is claimed is narrow: the exact behavior of this one complete FDE window (no calls inside, no branch leaving it, a single ret on the only path), with no claim about the input's meaning or what consumes the result.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_bsr_shift_mask.py --check research/work-items/foundation-bsr-shift-mask-94/evidence.json
python3 -m unittest tests.test_foundation_bsr_shift_mask -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x54b4390 --stop-address=0x54b43e0 artifacts/node/94/hl-node
objdump -d --start-address=0x54c5620 --stop-address=0x54c7547 artifacts/node/94/hl-node
objdump -d --start-address=0x54c7550 --stop-address=0x54c8ca5 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window plus its 14 trailing int3 padding bytes (the export stops at the next FDE start). The `caller.objdump.txt` file retains complete disassembly of the two caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2bf8c8` (this window), `0x2bf8dc` (the next FDE), `0x2bfecc` and `0x2bff34` (the two caller FDEs), plus the CIE at offset `0` (all four FDEs). The checker locks these raw FDE records and the CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

- FDE record at `.eh_frame` section offset `0x2bf8c8`, CIE at offset `0`
  (`zR`, pcrel sdata4), range 66 bytes. The 66-byte body ends at `0x54b43d2`;
  14 `int3` padding bytes run to the 80-byte stride ending at `0x54b43e0`,
  where the next FDE starts (`[0x54b43e0, 0x54b4425)`, section offset
  `0x2bf8dc`, same CIE). Stride is not the FDE extent; the checker locks
  body and padding separately.
- Decoded instructions, in order, all verified from bytes (all arithmetic
  64-bit except the final lea into eax):
  - `lea -0x1(%rdi,%rdi,1),%rax` (rax = 2*rdi − 1); `mov $0x7,%ecx`;
    `mov %rdi,%rdx` (input saved); `mov $0xffffffffffffffff,%rdi`
    (all-ones mask); `bsr %rax,%rsi` (rsi = bsr(2*rdi − 1)).
  - `mov $0x6,%r8d`; `cmp %ecx,%esi; cmovae %esi,%ecx` gives
    `ecx = max(7, bsr)` (unsigned); `sub $0x1,%rdx` (rdx = rdi − 1);
    `sub $0x3,%ecx` gives `shift = max(7, bsr) − 3`.
  - `shl %cl,%rdi` (mask = −1 << shift); `and %rdx,%rdi`;
    `shr %cl,%rdi`; `and $0x3,%edi` gives
    `masked = (((rdi − 1) & (−1 << shift)) >> shift) & 3`.
  - `cmp %r8d,%esi; cmovb %r8d,%esi` gives `clamped = max(bsr, 6)`;
    `lea -0x17(%rdi,%rsi,4),%eax` gives `eax = masked + 4*clamped − 0x17`;
    `ret`.
- Rule, stated literally: `bsr = bsr(2*rdi − 1)`; `shift = max(7, bsr) − 3`;
  `masked = (((rdi − 1) & (−1 << shift)) >> shift) & 3`;
  `result = masked + 4*max(bsr, 6) − 0x17` (32-bit eax). No field is written.
- Bsr-defined caveat, stated exactly: `2*rdi − 1` is odd for every 64-bit
  input, so it is never zero and the bsr is architecturally defined on all
  inputs — unlike packet #49, no zero-input exclusion is needed. The shift
  count uses only the low 6 bits of cl in hardware, but `shift` here lies in
  4..60, so no masking effect arises.
- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
  exactly two direct `e8` sites, both boundary-confirmed above. This is
  explicitly not a complete xref census.
- Data edge: no relocation record of any type in any `.rela.*` section
  names this window as addend (full-section scan: 80,022 `.rela.dyn` +
  278 `.rela.plt` entries).
- Entry shape: the window does NOT open with endbr64 (it opens directly
  with the lea); it has zero branches (cmov only) and a single ret.

## Inferences

- The label "bsr-derived shift-mask" is an inference from the instruction
  sequence (one bsr, one shift-and-mask extraction, one linear term). It is
  kept separate from the observed rule above.
- Nothing is inferred about what the input represents, what the two-bit
  masked field means, or which source-level function this window belongs to.

## Unknowns

- Whether the two callers pass related inputs, and what consumes the
  returned value, is unknown; the caller FDEs are retained but their
  purposes are not claimed.
- Whether this window shares a source-level helper with packets #49 or #95
  is unknown and not claimed; only the byte-level rule differences above
  are established.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is
  claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a
  naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated
  progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was
  copied, and every claim is grounded in target bytes for node #94.
