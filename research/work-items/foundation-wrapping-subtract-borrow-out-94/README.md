# foundation-wrapping-subtract-borrow-out-94: what does the four-limb wrapping subtract window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 81-byte FDE window with fifteen padding bytes, the four-limb wrapping subtract rule with its exact fields and borrow-out byte, the exact incoming-call scan result (two direct sites, both boundary-confirmed in one caller FDE), and the zero naming-relocation-slot result.
- Excluded: what the 256-bit values mean, what the subtraction is for, what the caller does with the result, any wider subtract family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a branchless four-limb subtract that rewrites its minuend in place, copies the difference unconditionally to a destination, and reports the borrow-out as a byte. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x32d8310`, no open pull request title mentions it or wrapping-subtract-borrow-out, and its bytes overlap nothing in packets #1–#116. Its provenance is the round-21 general slice, not any peer lane: the peer lanes scouted in round 21 yielded zero rankable items, and nothing here re-claims, re-states, or grades any peer's work.

## Scout note

The round-21 scout note listed this window (ranked #1, the round's only rankable item) with FDE `[0x32d8310, 0x32d8361)`, 81 bytes, 15 padding bytes, straight-line with zero calls inside, 2 direct callers in one caller FDE `[0x3299180, 0x32996b6)`, 0 naming slots, and nearest claimed window `0x3290130` `0x481e0` away. Every element verified exactly. One precision refinement: the scout's limb-3 sketch compressed the borrow-capture order. The bytes show the exact order is `setb %cl` (limb-2 borrow) *before* the top subtract, then `setb %dl` (top-subtract borrow) after it, then the `add $0xff,%cl` / `sbb $0,%rax` pair that applies the limb-2 borrow. The net rule is unchanged; the README below records the verified order, not the compressed sketch.

## Caveats, stated head-on

- **Checked-subtract distinction (mandatory).** The claimed packet at `0x2760a10` (foundation-checked-subtract-94) is also a four-word sub/sbb chain with the `add $0xff` borrow-in trick, so the relationship is stated explicitly, not hidden. The two operations differ, verified from bytes by this builder:
  - Semantics: `0x2760a10` is checked — it has TWO branches (`jb` at `0x2760a49`, `jne` at `0x2760a4d`) gating the result copy (on failure `out+8` is untouched) and stores a success flag (1/0) at `out+0`. `0x32d8310` is wrapping — it is branchless, copies unconditionally, and stores a borrow-out byte at `out+0x20`.
  - Operand roles: in `0x2760a10` `[rsi]` is the subtrahend and `[rdx]` the minuend; in `0x32d8310` `[rsi]` is the minuend and `[rdx]` the subtrahend.
  - Size: 87 bytes vs 81 bytes.
  - Byte-compare over the overlap, run by this builder against the target bytes at `0x2760a10`: only **23/81** identical — not a twin.
  - Callers: one caller FDE with 3 sites vs one caller FDE with 2 sites.
  Same 256-bit-subtract idiom, different operation (checked_sub-style vs overflowing_sub-style). Nothing here re-claims `0x2760a10`.
- **Neighbourhood populations, not members.** The `0x32d8b20+` run (110–127B, prologue `53 4883ec50…`) are stack-building wrappers that CALL `0x2aead80`, and the `0x32d57f0+` run (100B, same prologue bytes) is a separate population. This window (81B, prologue `488b02…`, straight-line arithmetic, no calls) belongs to neither.
- **Symbol-label disclaimer.** GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it. In particular, no stdlib or private provenance is claimed either way.
- **Caller scale, stated plainly.** Two direct callers in one caller FDE is a small, retained fact (the caller FDE is kept in full in `caller.objdump.txt`), not a population claim. The byte-pattern scan is not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope.
- **Thinness, stated plainly.** This is a single-purpose window: one subtract chain, one unconditional copy, one borrow byte, one return. What it is not is ambiguous — the limb offsets, the borrow chain, and the borrow-out position are all fixed by the bytes with no room for an alternate reading. The packet claims exactly that one rule and nothing more.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_wrapping_subtract_borrow_out.py --check research/work-items/foundation-wrapping-subtract-borrow-out-94/evidence.json
python3 -m unittest tests.test_foundation_wrapping_subtract_borrow_out -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x32d8310 --stop-address=0x32d8370 artifacts/node/94/hl-node
objdump -d --start-address=0x3299180 --stop-address=0x32996b6 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its fifteen padding bytes. The `caller.objdump.txt` file retains complete disassembly of the caller FDE. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x1095cc` (this window), `0x1095e0` (the next FDE), `0x107258` (the caller FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x1095cc` describes `[0x32d8310, 0x32d8361)`, 81 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Fifteen `int3` bytes follow: the next FDE starts exactly at `0x32d8370` (record at `.eh_frame+0x1095e0`, range to `0x32d8640`). The unwind-index stride is therefore 96 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `mov (%rdx),%rax`, not `endbr64` — the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x32d8310`. `[rsi]` is the minuend, `[rdx]` the subtrahend, `[rdi]` the destination. Limbs are 64-bit, little-endian.

- Offset `0x00`: `mov (%rdx),%rax` — limb-0 subtrahend load.
- Offset `0x03`: `sub %rax,(%rsi)` — limb-0 subtract; CF is borrow0. `[rsi+0x00]` now holds limb-0 of the difference.
- Offset `0x06`: `mov 0x8(%rdx),%rax` — limb-1 subtrahend load.
- Offset `0x0a`: `sbb %rax,0x8(%rsi)` — limb-1 subtract with borrow0; CF is borrow1.
- Offset `0x0e`: `mov 0x10(%rdx),%rax` — limb-2 subtrahend load.
- Offset `0x12`: `sbb %rax,0x10(%rsi)` — limb-2 subtract with borrow1; CF is borrow2.
- Offset `0x16`: `mov 0x18(%rsi),%rax` — top minuend load.
- Offset `0x1a`: `setb %cl` — borrow2 captured into cl *before* the top subtract.
- Offset `0x1d`: `sub 0x18(%rdx),%rax` — top subtract; CF is the top-subtract borrow.
- Offset `0x21`: `setb %dl` — top-subtract borrow captured into dl.
- Offset `0x24`: `add $0xff,%cl` — the borrow-in trick: adding 0xff to cl sets CF iff cl was 1, i.e. iff borrow2 was 1.
- Offset `0x27`: `sbb $0x0,%rax` — top difference: rax minus borrow2; CF is the sbb borrow.
- Offset `0x2b`: `setb %cl` — sbb borrow captured into cl.
- Offset `0x2e`: `or %dl,%cl` — borrow-out: top-subtract borrow OR sbb borrow.
- Offset `0x30`: `and $0x1,%cl` — borrow-out normalized to 0/1 (both inputs are already 0/1, so this is a no-op normalization, locked as observed).
- Offset `0x33`: `mov %rax,0x18(%rsi)` — top difference stored; `[rsi]` now holds all four difference limbs in place.
- Offset `0x37`: `movups (%rsi),%xmm0` — low two difference limbs load.
- Offset `0x3a`: `movups %xmm0,(%rdi)` — low copy (unconditional).
- Offset `0x3d`: `mov 0x10(%rsi),%rax` — limb-2 difference load.
- Offset `0x41`: `mov %rax,0x10(%rdi)` — limb-2 copy.
- Offset `0x45`: `mov 0x18(%rsi),%rax` — top difference load.
- Offset `0x49`: `mov %rax,0x18(%rdi)` — top copy.
- Offset `0x4d`: `mov %cl,0x20(%rdi)` — borrow-out byte store.
- Offset `0x50`: `ret` — single return; zero branches, zero calls inside.

The rule is therefore: `[rdi+0x00..0x20]` = `[rsi] − [rdx]` over four 64-bit limbs (wrapping), `[rsi]` rewritten in place with the same difference, and `[rdi+0x20]` = borrow-out byte (1 iff the 256-bit minuend is strictly smaller than the subtrahend). The copy to `[rdi]` is unconditional — no branch gates it — which is exactly what separates this window from the branch-gated checked-subtract packet.

### Incoming calls

- The `.text` byte-pattern scan (70,370,352 bytes) finds exactly two direct `e8` sites whose rel32 lands on the window start: `0x32994ed` and `0x3299579`.
- Both sites are boundary-confirmed inside the single caller FDE `[0x3299180, 0x32996b6)` by linear disassembly from that FDE start. The caller FDE is retained in full in `caller.objdump.txt`.
- This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan.

### Relocation slots

- Full-section scan of `.rela.dyn` (80,022 entries) and `.rela.plt` (278 entries) finds zero `R_X86_64_RELATIVE` records naming this window as addend. The window carries no naming slot; that absence is itself the retained result, and no meaning is claimed from it.

### Byte comparisons

- Claimed checked-subtract window `0x2760a10`: 23/81 bytes identical over this window's extent — not a twin (see the distinction above).
- Nearest claimed packet window `0x3290130`: `0x481e0` away; no closer claimed window exists in the `0x32d8xxx` neighbourhood, and the neighbouring `0x32d8b20+` / `0x32d57f0+` runs are different populations (see above).

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere. The "four-limb wrapping subtract with borrow-out byte" label is an inference, kept separate from the observed rule.
- The byte-pattern scan is not a complete xref census, and the absence of a relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
