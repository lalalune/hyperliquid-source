# RE-001: map node #115 group-report formatter 0x5f6c320

## Task

RE-001. Bounded question: what text does the whole formatter at
0x5f6c320 write into its caller buffer — when does it emit the
base-level prefix line, how does it render each group, and when does
it append the compaction suffix?

## Evidence

- Artifact: work/hl-node-115.bin, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.
- Packet: research/work-items/RE-001-group-report-formatter-115/ —
  semantic records.json only (no per-instruction mnemonic list); one
  whole-function verbatim excerpt; frames.txt; relocations.txt;
  verify.py, export_excerpts.py and census.py committed in the packet;
  MANIFEST.sha256. Mnemonics such as `endbr64` in the excerpt are genuine
  instructions present in the target binary, not placeholders. The
  objdump command for the excerpt is recorded in export_excerpts.py.
- Window: formatter 0x5f6c320..0x5f6c4d7 (439 bytes, FDE at file
  offset 0x1004dd8, length 0x54, CIE at .eh_frame start).
- Layout: obj+0xa90 is the flag byte; obj+0x10 the signed 32-bit
  group count; obj+0xaf8 the double multiplier; obj+0xaf0 the signed
  32-bit base level; obj+0x18 a qword array indexed by that level;
  obj+0xa98 the array of 24-byte group entries (begin qword, end
  qword, third qword never read); obj+0xf38 a pointer to the max-score
  double; obj+0xbd0, obj+0xbc8 and obj+0xb38 the compaction-count
  qwords. The field layout for the group array (count at +0x10,
  entries at +0xa98) is corroborated by the neighbouring group windows
  mapped in the group-stamp work item (predicate 0x5f6c4e0, maximum
  0x5f6c540, caller 0x5f6c5a0), which read the same fields; those
  windows are not re-claimed here.
- Semantics, stated literally: the buffer is 1000 bytes and the
  function returns the buffer pointer. The special prefix line is
  written exactly when the flag byte at obj+0xa90 is 0, the signed
  group count is greater than 1, and the double at obj+0xaf8 is not
  +0.0 under ucomisd (NaN takes the branch; -0.0 does not): the line
  is `base level %d level multiplier %.2f max bytes base %lu ` with
  the signed base level, the multiplier double, and the qword at
  [[obj+0x18] + level * 8]. Otherwise the buffer starts empty. Then
  `files[` is appended (6 chars) and, when the count is positive, one
  `%d ` line per group i in 0..count-1 with the element count
  (entry.end - entry.begin) >> 3, arithmetic shift on the wrapped
  64-bit difference, printed as C %d (low 32 bits, signed); a group
  line whose snprintf return is negative or reaches the remaining
  space breaks the loop with the tracked offset unchanged. After the
  loop the tracked offset is reduced by 1 when it is positive,
  dropping the trailing space (or the `[` when no group line ran).
  Then `] max score %.2f` is appended with the double at
  [obj+0xf38]. Finally, with need = (([obj+0xbd0] - [obj+0xbc8]) >> 4,
  arithmetic) + [obj+0xb38], wrapping at 64 bits, the suffix
  ` (%zu files need compaction)` is appended with need when need is
  nonzero, and nothing further is written when need is zero.
- Census (whole-file scan, reproduced by the packet's census.py):
  the formatter has exactly 6 direct calls (sites only: 0x5dc6b08,
  0x5de3cf5, 0x5de729d, 0x5df6005, 0x5e0b763, 0x5e84bfb), 0 tail
  jumps, no stored 8-byte qword, and no RELATIVE addend. Its only
  callees are libc snprintf (for `files[`) and __snprintf_chk (for
  every other append), recorded but not otherwise modelled.
- Unknowns: the snprintf truncation arms are not pinned (tests keep
  total output well under 1000 bytes); the domain meaning of the
  groups, the max score and the compaction count is not claimed; the
  six call sites are sites only; a negative base-level array index
  is not exercised; %.2f rounding agreement between Python and glibc
  printf is established on the tested values only.

## Model and tests

- tools/group_report_formatter_115.py — the formatter model, returning
  the buffer text in the non-truncating regime.
- tests/test_group_report_formatter_115.py — 12 tests: empty and
  multi-group normal paths, the special prefix and every gate
  condition (flag, count, +0.0, -0.0, NaN), the compaction suffix
  with its arithmetic and unsigned wrap, %d truncation, first-count
  slicing, negative counts, max-score formatting, and packet checks.
