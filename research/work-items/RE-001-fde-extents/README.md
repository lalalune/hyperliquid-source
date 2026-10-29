# RE-001: Do the #94 and #115 FDE records agree with the unwind index, and which .text bytes have none?

- Component ID: none (binary-wide function-map input; no component ownership)
- Target release and full SHA-256: node #94
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (baseline);
  node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (separate target, reported side by side, no #94 addresses reused)
- Source commit / reference commit: hyperliquid-source `6fb86319763b30860f92b9da746cbe4f9b637573`;
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (not used by this packet)
- Claim status: observation (FDE extents, gap byte classes); unresolved (what the
  non-int3 gaps contain, function boundaries)
- Scope included: every `.eh_frame` CIE/FDE record, its consistency with the
  `.eh_frame_hdr` binary-search table, and the `.text` bytes no FDE covers.
- Scope excluded: CFA instructions, LSDA contents, call graph, cross-references,
  entrypoint validation, function ownership. RE-001 is **not** complete.

## Reproduce

Platform: Ubuntu 24.04.3 LTS under WSL2 (Linux 6.6.87.2 x86_64), Python 3.12.3,
GNU readelf 2.42. Static parsing only; no captured binary is executed.

```sh
make verify
make fde-index        # writes work/index/node-{94,115}-fde{.tsv,.json,-gaps.tsv}
python3 research/work-items/RE-001-fde-extents/readelf_crosscheck.py --release 94
python3 research/work-items/RE-001-fde-extents/readelf_crosscheck.py --release 115
```

`tools/fde_extents.py` verifies the artifact digest, decodes `.eh_frame`, and
fails closed on anything outside the captured encodings: CIE version 1,
augmentation `z` with `R`/`P`/`L`/`S`, FDE/LSDA pointers `0x1b`
(pcrel|sdata4), personality `0x9b` (indirect|pcrel|sdata4, slot address
recorded, never dereferenced), 32-bit record lengths and a zero terminator
followed only by zero bytes. A raw zero LSDA is null, as in libgcc.

Generated outputs (identical on a second run; SHA-256):

| File | Rows | SHA-256 |
| --- | ---: | --- |
| node-94-fde.tsv | 121,299 | `2bd6c306cf4eaceea349118d5db0cb681f9ca2d857bb9594d6220b2e62ba512a` |
| node-94-fde-gaps.tsv | 113,154 | `592f88ef313db06a2b1aae40e533e6e3e0aebfd421b1fe2b5936e74f68b7b4cc` |
| node-94-fde.json | — | `81019ea6e508a15c60106145556efa848b2a6c75a21bcc22ca1b334f6f307cbc` |
| node-115-fde.tsv | 135,313 | `bb2dc2ed0f9871d854460d4ea04b8b9c8a7512b91e5b5dd5ee319f20ef566447` |
| node-115-fde-gaps.tsv | 126,775 | `808ba65fe81d9bd50dca252d521a449c620b53cdb3363f2e741c393d7d66765b` |
| node-115-fde.json | — | `92dc640e69f705551db09393cbdceaf088d9bd35bf2961e7c5a6d3605f97cee1` |

The full TSVs stay in ignored `work/`. Retained here: each JSON summary
(`node-*-fde-summary.json`), the readelf comparison (`node-*-readelf-crosscheck.json`)
and only the gaps that are not pure `0xcc` (`node-*-other-byte-gaps.tsv`).

## Evidence

Coordinates are linked virtual addresses from the ELF section table.

| Observation | #94 | #115 |
| --- | ---: | ---: |
| CIE records (`zR` / `zPLR`) | 3 (1 / 2) | 3 (1 / 2) |
| FDE records | 121,299 | 135,313 |
| `.eh_frame_hdr` table entries | 121,299 | 135,313 |
| FDEs absent from the table | 0 | 0 |
| Table start ≠ its FDE's `pc_begin` | 0 | 0 |
| Duplicate starts / zero-length / overlapping pairs | 0 / 0 / 0 | 0 / 0 / 0 |
| Extents crossing a section end | 0 | 0 |
| FDEs with an LSDA (all inside `.gcc_except_table`) | 50,493 | 52,682 |
| Extent end = next index start (old upper bound exact) | 8,145 | 8,538 |
| Extent end > next index start | 0 | 0 |
| `.text` bytes / FDE-covered bytes | 70,370,352 / 69,397,415 | 83,719,936 / 82,661,417 |
| Same-section gaps that are only `0xcc` (count / bytes) | 113,020 / 907,353 | 126,642 / 992,570 |
| Gaps containing other bytes (count / bytes) | 134 / 65,584 | 133 / 65,949 |
| `.init` / `.fini` / `.plt` bytes with no FDE | 27 / 13 / 4,464 | 27 / 13 / 4,464 |

- **Independent decoder:** GNU readelf 2.42 `--debug-dump=frames` reports the
  same CIE count and the identical set of (pc_begin, pc_end, FDE address)
  triples for both binaries: 0 only-in-tool, 0 only-in-readelf.
- **Byte accounting closes:** for #94, `.text` minus FDE coverage is 972,937
  bytes = 907,353 int3-only + 65,584 other-byte gap bytes; no bytes precede the
  first FDE (`0x1343c80`, the `.text` start) or follow the last. #115 closes the
  same way (1,058,519 bytes).
- **The next-index upper bound overstates extents:** in 113,154 #94 rows the
  true FDE end is below the next indexed start; it is never above it.
- **Other-byte gaps:** 130 of the 134 #94 gaps are at most 64 bytes. The three
  largest are 60,675 bytes at `0x54a54dd`, 2,493 bytes at `0x5631543` and
  195 bytes at `0x1343ca6`. Some gaps begin with multi-byte NOP encodings
  (e.g. `0x5653254`: `90 66 66 2e 0f 1f 84 00 …`), so "other bytes" is not
  "code". After 35 `0xcc` bytes, the first non-fill bytes at `0x54a5500` are
  `f3 0f 1e fa 41 57 41 56 41 55 41 54` (objdump 2.42: `endbr64; push %r15; …`).
- Analysis was complete for both binaries (about 1 s each, single pass).
  The binaries are stripped (no `.symtab`), so no gap is named here.

## Implementation and comparison

No Rust implementation or binary comparator: this packet is deterministic offline
tooling and static observation. Tooling controls in `tests/test_fde_extents.py`
build a synthetic ELF with both augmentation kinds, an LSDA, a null LSDA, an
int3 gap and a non-int3 gap. They check decoding, and that corruption is either
counted (overlap, table start ≠ FDE start, FDE missing from the table) or
rejected (unsupported pointer encoding or augmentation, 64-bit length, bad CIE
pointer, augmentation length mismatch, negative range, missing terminator,
bytes after the terminator, `eh_frame_ptr` mismatch, table entry that is not an
FDE). Seven deliberate decoder mutations (pc-relative base, null LSDA, negative
range, start mismatch, overlap test, gap class, terminator tail) each fail
those tests.

## Results and limitations

- FDE extents are unwind-described address ranges, **not validated function
  boundaries**. Split hot/cold parts would appear as separate FDEs; code
  without unwind data has none. They supply a per-binary candidate denominator
  only after boundaries and duplicates are validated by CFG/data analysis.
- Gap classes are byte patterns. Whether each other-byte gap is NOP fill,
  data, or code without CFI (and which library emitted it) is unresolved.
- No progress gate is requested; every component gate stays false.

Next question: for each of the 134 #94 other-byte gaps, which bytes are
alignment NOPs, and do the remaining regions (starting with `0x54a5500` and
`0x5631580`) disassemble into code with a validated entrypoint and caller?
