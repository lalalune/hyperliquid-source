# RE-001: map node #115 element-rate pass 0x5f6b660

Task: RE-001. Bounded question: what does the whole 181-byte function at
0x5f6b660 do to the object it is called on, end to end?

## Answer, stated literally

The function computes one unsigned rate from four object fields, then
walks every group of the object and stamps each not-yet-stamped element
with a value derived from that rate.

Rate (all values unsigned 64-bit, wrapping at 64 bits):

- If obj+0xfa0 == 0, the rate is 0 and no division runs.
- Otherwise rate = (((obj+0xf98 // obj+0xfa0) * obj+0xf88) mod 2**64)
  // ((obj+0xf98 + obj+0xf90) mod 2**64).

Read the first division carefully: its dividend is obj+0xf98 **alone**.
obj+0xf90 is added to obj+0xf98 only for the final divisor. A reader
who folds the add into the first dividend gets a different rate (the
model test `rate_dividend_is_f98_alone` separates the two readings:
f98=90, fa0=7, f90=10, f88=100 gives 12, not 14). When obj+0xfa0 != 0
and (obj+0xf98 + obj+0xf90) wraps to zero, the second division traps
in the native code; the model raises a guard error instead. The rate
block runs **before** the group-count check, so that trap fires even
when the count is non-positive.

Pass: if the signed 32-bit group count at obj+0x10 is <= 0, return
without touching any element. Otherwise walk groups 0..count-1 in
order (24-byte entries at obj+0xa98; begin, end, third qword never
read). An empty group contributes nothing. For each element pointer in
a group, in order: if element+0x78 is nonzero, skip the element
entirely. Otherwise, with all arithmetic wrapping at 64 bits:

- delta2 = 2 * ((element+0x88 - element+0xa0) mod 2**64) mod 2**64
- if delta2 < element+0x80 (unsigned): result = element+0x10
- else: result = element+0x10
  + 2 * (((delta2 - element+0x80) * rate) mod 2**64) mod 2**64
- element+0x78 = (result + element+0xa8) mod 2**64

The pass is idempotent: a second run recomputes the same +0x78 values
from inputs the first run never changes.

## Evidence

- Binary: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  bound in provenance/artifacts.json as artifacts/node/115/hl-node.
- Window: 0x5f6b660..0x5f6b715 (181 bytes), FDE file offset 0x1004c78,
  length field 0x10, CIE at .eh_frame start (augmentation "zR"),
  no LSDA field. See frames.txt.
- `excerpts/pass.txt` is the whole-function disassembly exactly as
  objdump emitted it, produced by:
  `objdump -d --start-address=0x5f6b660 --stop-address=0x5f6b715 work/hl-node-115.bin`
  (run from the clone root; export_excerpts.py does the same).
  Instruction-level detail lives in that excerpt only; records.json
  holds semantic records (branch sites, fields, census), not a
  per-instruction list. The `endbr64` at the window start is a genuine
  instruction present in the target binary, not a placeholder.
- Census (whole-file scan, reproduced by census.py): exactly one
  direct call, site 0x5f884c1, inside the 0x5f884b0 pipeline function,
  which calls this pass first; 0 tail jumps, 0 stored qwords,
  0 RELATIVE addends. That caller is recorded as a site only; its
  other callees are not modelled here.
- Model: tools/element_rate_pass_115.py. Tests:
  tests/test_element_rate_pass_115.py (16 tests, run under plain
  python3 via its `__main__` runner; pytest is not installed on this
  VM).
- verify.py re-checks the digest and its provenance binding, the
  manifest, excerpt regeneration byte-for-byte from a fresh objdump
  run, 5 gate + 3 extra instructions byte-for-byte against a fresh
  objdump run and against the raw binary bytes, the FDE range, the
  census, and the model tests. It prints ALL CHECKS PASSED on success.

## Assumptions and unknowns

- The group entries' third qword is never read by this window; its
  meaning is unknown and not claimed.
- The object fields +0xf88/+0xf90/+0xf98/+0xfa0 are named by their
  roles in the rate formula only; their higher-level meanings (what
  the rate prices) are not established by this window and not claimed.
- The sole caller's pipeline (0x5f884b0) calls this pass first and
  then a trailing-empty-group trim and further passes; the ordering
  after this pass is not modelled here.
- Environment limits, stated honestly: this VM has no cargo/rustc,
  no git-lfs and no Ghidra/Java, so no Rust reconstruction is claimed
  and the packet binds to the materialized work/hl-node-115.bin rather
  than the LFS-pointer artifact.
