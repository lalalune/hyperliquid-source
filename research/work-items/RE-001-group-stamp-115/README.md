# RE-001: map node #115 group-stamp caller 0x5f6c5a0 with its predicate 0x5f6c4e0 and maximum 0x5f6c540

## Task

RE-001. Bounded question: how does the caller at 0x5f6c5a0 assign the
+0xd0 stamp field of a group's elements — when does it stamp, in what
order, with what values, and what does it write back to its counter
slot when it does not stamp?

## Evidence

- Artifact: work/hl-node-115.bin, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.
- Packet: research/work-items/RE-001-group-stamp-115/ — semantic
  records.json only (no per-instruction mnemonic list); whole-function
  verbatim excerpts for all three windows; frames.txt; relocations.txt;
  verify.py, export_excerpts.py and census.py committed in the packet;
  MANIFEST.sha256. Mnemonics such as `endbr64` in the excerpts are genuine
  instructions present in the target binary, not placeholders. The
  objdump command for each excerpt is recorded in export_excerpts.py.
- Windows: predicate 0x5f6c4e0..0x5f6c53c (92 bytes); maximum
  0x5f6c540..0x5f6c59d (93 bytes); caller 0x5f6c5a0..0x5f6c734 (436 bytes).
- Layout: obj+0x10 is the signed 32-bit group count; obj+0xa98 is the
  array of 24-byte group entries (begin qword, end qword, third qword
  never read); elements are 8-byte pointers in [begin, end);
  element+0xd0 is the stamp field; arg2+0x9e0 is the counter slot;
  arg2+0x4fb is the flag byte; obj+0xfd4 is written to 1 only on the
  stamp path.
- Semantics, stated literally: the caller first writes 1 to the
  counter slot with xchg (the previous value is discarded). When the
  flag byte at arg2+0x4fb is nonzero, it increments the slot once
  (lock xadd) and makes a log call (callee 0x5fceda0, level 1, file
  string `db/version_set.cc`, format `[%s:4376] [%s]CF has reserved
  epoch number %lu for files ingested behind since
  `Options::allow_ingest_behind` is true`). It then calls the
  predicate 0x5f6c4e0, which returns 1 when any element in
  groups[0:count] has stamp 0 and 0 otherwise (a non-positive count
  returns 0 without reading any group). On the stamp path it walks
  groups count-1 down to 1 in that order: each non-empty group takes
  exactly one fresh slot value (lock xadd) and stamps every element
  of that group with it; then group 0 is stamped per element,
  walking its elements in reverse order with one fresh slot value
  each (an empty group 0 takes no value). Afterwards it makes a
  second log call (level 2, same file string, format `[%s:4404]
  [%s]CF's epoch numbers are inferred based on seqno`) and writes 1
  to obj+0xfd4; the slot is left at its last incremented value. On
  the max path (no zero stamp) it calls the maximum 0x5f6c540, which
  returns the largest element stamp over groups[0:count] under an
  unsigned compare starting from 0 (so an empty selection yields 0),
  and writes max(max_stamp + 1, current slot) — max_stamp + 1
  wrapping at 64 bits, compared unsigned — back to the slot with
  xchg; obj+0xfd4 is untouched.
- Census (whole-file scan, reproduced by the packet's census.py):
  the predicate has exactly 3 direct calls (this caller's sites
  0x5f6c5cd and 0x5f6c704 plus 0x5f52d1a, site only) and no tail
  jump; the maximum has exactly 1 direct call (this caller's site
  0x5f6c71c, sole consumer) and no tail jump; the caller has
  exactly 1 direct call (site 0x5eeaa6f, site only) and exactly 1
  tail jump (site 0x5d8ce6f, site only). No window address appears
  as a stored 8-byte qword anywhere in the file or as the addend
  of any R_X86_64_RELATIVE relocation.
- Unknowns (kept separate): the domain meaning of the groups and of
  the +0xd0 stamp beyond the quoted log strings is not claimed; the
  other predicate call site and the caller's direct-call and
  tail-jump sites are sites only, not modelled; the log callee
  0x5fceda0 and its argument-to-format mapping are not modelled;
  the native %rax on return (log callee return on the stamp path,
  previous slot value on the max path) is not part of the pinned
  contract.

## Verification

- Packet checker ALL CHECKS PASSED: digest, provenance, manifest,
  excerpt regeneration byte-for-byte from a fresh objdump run,
  sampled + 3 gate instructions byte-for-byte vs fresh objdump and
  raw binary, frames, census, model tests.
- 11 model tests pass (tools/group_stamp_115.py,
  tests/test_group_stamp_115.py): predicate edges, unsigned maximum,
  multi-group stamp order and values, single-group stamp, flag-first
  increment, empty middle group consuming no value, empty group as
  max path, plain max path, slot clamp, 64-bit wrap, guards, packet
  checks.
- Environment limits, stated honestly: this VM has no cargo/rustc,
  no git-lfs and no Ghidra/Java; `make doctor` fails on missing
  providers (pre-existing); `make verify` / `make catalogue-check`
  fail on the LFS-pointer artifact here (pre-existing — this packet
  binds to the materialized work/hl-node-115.bin instead); pytest is
  not installed, so the pytest-style file ran under plain python3
  via its `__main__` runner.
