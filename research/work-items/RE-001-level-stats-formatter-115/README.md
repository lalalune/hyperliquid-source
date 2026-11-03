# RE-001: map node #115 level-stats formatter 0x5eecbb0 with its group sum 0x5f6c300 and leaf 0x5da4de0

## Task

RE-001. Bounded question: what does the getter-shaped function at
0x5eecbb0 write into its output string — the level table for the
sub-object at [outer + 0x788] + 0x30 — and how are its per-level
numbers computed end to end?

## Evidence

- Artifact: work/hl-node-115.bin, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.
- Packet: research/work-items/RE-001-level-stats-formatter-115/ — semantic
  records.json only (no per-instruction mnemonic list); whole-function
  verbatim excerpts for all three windows; frames.txt; relocations.txt;
  verify.py, export_excerpts.py and census.py committed in the packet;
  MANIFEST.sha256. Mnemonics such as `endbr64` in the excerpts are genuine
  instructions present in the target binary, not placeholders. The
  objdump command for each excerpt is recorded in export_excerpts.py.
- Windows: getter 0x5eecbb0..0x5eecd7e (606 bytes); group sum
  0x5f6c300..0x5f6c31b (27 bytes); leaf 0x5da4de0..0x5da4e1e (62 bytes).
- Semantics, stated literally: the getter appends the header
  "Level Files Size(MB)\n--------------------\n" (built on the stack from
  rodata chunks 0x456960, 0x4555c0 and 0x456c70, the third overwriting
  at offset 27) to the output string, then, for i in 0..count-1 where
  count is the signed 32-bit value at [outer + 0x778], appends one line
  formatted with rodata 0x436160 "%3d %8d %8.0f\n" as
  (i, element_count(i), size_mb(i)). The group entry for level i is
  the 24-byte record at [sub + 0xad8] + i * 24 (its third qword is never
  read); element_count(i) is (entry.end - entry.begin) >> 3, an
  arithmetic shift on the wrapped 64-bit difference. The group sum
  0x5f6c300 reads the group array base as [sub + 0xad8] (via its
  argument (sub + 0x40) + 0xa98), selects entry i, and tail-jumps to
  the leaf 0x5da4de0, which sums [element + 0x10] over the non-null
  8-byte element pointers in [entry.begin, entry.end), wrapping at 64
  bits, and returns 0 for an empty range. size_mb(i) is the unsigned
  reading of that wrapped sum converted to double and multiplied by
  the rodata double at 0x459638, exactly 2**-20 (1 MiB). The getter
  returns 1 unconditionally, including for a non-positive count, which
  yields the header alone.
- Census (whole-file scan, reproduced by the packet's census.py): the
  getter has 0 direct calls, 0 tail jumps, 0 qword hits and 0 RELATIVE
  addends (virtual-getter shape); the group sum has exactly 4 direct
  calls (this getter's site 0x5eeccf5 plus 0x5d52c15, 0x5ef22a2 and
  0x5ef2374, sites only); the leaf has exactly 5 direct calls (sites
  only) and exactly 1 tail jump, the group sum's site 0x5f6c316.
- Unknowns (kept separate): the domain meaning of the levels and the
  level groups is not claimed; the other call sites of the group sum
  and the leaf are sites only, not modelled; a group range whose end
  precedes its begin is refused by the model rather than given an
  invented result, because the native leaf loop would run unbounded
  there; appending past the output string's maximum length throws a
  length error natively and is likewise refused by the model.

## Verification

- Packet checker ALL CHECKS PASSED: digest, provenance, manifest,
  excerpt regeneration byte-for-byte from a fresh objdump run, sampled
  + 3 gate instructions byte-for-byte vs fresh objdump and raw binary,
  frames, census, model tests.
- 12 model tests pass (tools/level_stats_formatter_115.py,
  tests/test_level_stats_formatter_115.py): header constant, zero and
  negative counts, single-level and empty-group lines, null-pointer
  skipping, multi-level end-to-end output, fractional-megabyte rounding,
  wrapped-sum unsigned reading, wide level index, missing-group and
  missing-field guards, packet checks.
- Environment limits, stated honestly: this VM has no cargo/rustc, no
  git-lfs, and no Ghidra/Java, so no Rust reconstruction is claimed.
  `make doctor` reports analysis_ready false on missing providers
  (pre-existing); `make verify` / `make catalogue-check` fail on the
  LFS-pointer artifact here (pre-existing — this packet binds to the
  materialized work/hl-node-115.bin instead); pytest is not installed,
  so the pytest-style file ran under plain python3 via its `__main__`
  runner.
