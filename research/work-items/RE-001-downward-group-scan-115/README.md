# RE-001: map node #115 downward group scan 0x5d52bb0 with its index leaf 0x5f6c740, group sum 0x5f6c300 and leaf 0x5da4de0

## Task

RE-001. Bounded question: what does the function at 0x5d52bb0 return for
a count n — the downward scan over the sub-object's level groups at
[sub + 0xad8] — and how do its two callees (the index leaf and the
group sum) compute the values it compares end to end?

## Evidence

- Artifact: work/hl-node-115.bin, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.
- Packet: research/work-items/RE-001-downward-group-scan-115/ — semantic
  records.json only (no per-instruction mnemonic list); whole-function
  verbatim excerpts for all five windows; frames.txt; relocations.txt;
  verify.py, export_excerpts.py and census.py committed in the packet;
  MANIFEST.sha256. Mnemonics such as `endbr64` in the excerpts are genuine
  instructions present in the target binary, not placeholders. The
  objdump command for each excerpt is recorded in export_excerpts.py.
- Windows: scanner 0x5d52bb0..0x5d52c6f (191 bytes); stub
  0x60d5390..0x60d5395 (5 bytes); index leaf 0x5f6c740..0x5f6c750
  (16 bytes); group sum 0x5f6c300..0x5f6c31b (27 bytes); leaf
  0x5da4de0..0x5da4e1e (62 bytes).
- Semantics, stated literally: the scanner first calls the stub
  0x60d5390 with (outer + 0x700, obj); the stub is endbr64 followed by
  ret, so the call has no observable effect. It reads sub = [obj +
  0x30] and the group array at [sub + 0xad8] (24-byte entries, third
  qword never read) plus the index array whose base is [sub + 0x58].
  If n - 1 <= 0 as a signed 32-bit value (that is, n <= 1), it returns
  n. Otherwise it scans i from n - 1 downward: count_i is
  (entry_i.end - entry_i.begin) >> 3, an arithmetic shift on the
  wrapped 64-bit difference, i.e. the number of 8-byte pointers in
  group i's range. If count_i > 0 it steps to i - 1, returning 1 when
  i reaches 0, and otherwise continues. If count_i <= 0 it calls the
  index leaf 0x5f6c740 with (sub + 0x40, i), which returns
  [[sub + 0x58] + i * 8] with i sign-extended from 32 bits, and the
  group sum 0x5f6c300 with (sub + 0x40, n) — note the original n, not
  i — which selects entry n and tail-jumps to the leaf 0x5da4de0,
  which sums [element + 0x10] over the leading run of non-null
  element pointers in group n's range, wrapping at 64 bits and
  stopping at the first null pointer (which ends the sum rather than
  being skipped), returning 0 for an empty range. If that group-n sum
  is below the index value as an unsigned compare, the scanner
  returns i + 1; otherwise it steps to i - 1, returning 1 when i
  reaches 0, and otherwise continues.
- Census (whole-file scan, reproduced by the packet's census.py):
  the scanner has exactly 1 direct call (site 0x5ded3c7, site only)
  and no tail jump; the stub has exactly 116 direct calls (including
  this scanner's site 0x5d52bd7, sites only) and no tail jump; the
  index leaf has exactly 11 direct calls (including this scanner's
  site 0x5d52c06, sites only) and no tail jump; the group sum has
  exactly 4 direct calls (this scanner's site 0x5d52c15 plus
  0x5eeccf5, the #2320 getter's site, and 0x5ef22a2 and 0x5ef2374,
  sites only) and no tail jump; the leaf has exactly 5 direct calls
  (sites only) and exactly 1 tail jump, the group sum's site
  0x5f6c316, which is the call claimed by this work item. No window
  address appears as a stored 8-byte qword anywhere in the file or as
  the addend of any R_X86_64_RELATIVE relocation.
- Unknowns (kept separate): the domain meaning of the groups and of
  the index array is not claimed; the other call sites of the stub,
  the index leaf, the group sum and the leaf are sites only, not
  modelled; a group range whose end precedes its begin is refused by
  the model rather than given an invented result, because the native
  leaf loop would run unbounded there.

## Verification

- Packet checker ALL CHECKS PASSED: digest, provenance, manifest,
  excerpt regeneration byte-for-byte from a fresh objdump run, sampled
  + 3 gate instructions byte-for-byte vs fresh objdump and raw binary,
  frames, census, model tests.
- 14 model tests pass (tools/downward_group_scan_115.py,
  tests/test_downward_group_scan_115.py): small counts, all-nonempty
  scan to 1, empty-group return of i + 1, at/above-threshold
  continuation, the group-n (not group-i) comparison distinguished,
  single-null-pointer range counting as non-empty, leaf leading-run
  stop at the first null, unsigned comparison, wrapped sum, missing
  group/field guards, packet checks.
- Environment limits, stated honestly: this VM has no cargo/rustc, no
  git-lfs, and no Ghidra/Java, so no Rust reconstruction is claimed.
  `make doctor` reports analysis_ready false on missing providers
  (pre-existing); `make verify` / `make catalogue-check` fail on the
  LFS-pointer artifact here (pre-existing — this packet binds to the
  materialized work/hl-node-115.bin instead); pytest is not installed,
  so the pytest-style file ran under plain python3 via its `__main__`
  runner.
