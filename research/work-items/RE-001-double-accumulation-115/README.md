# RE-001: node #115 double-accumulation pass 0x5f6c750

Bounded question: what does the 0x5f6c750 pass compute, and what does it
leave in the cached total at obj+0xfc8?

Task: RE-001. Artifact: work/hl-node-115.bin, the node #115 binary, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(bound in provenance/artifacts.json as artifacts/node/115/hl-node).
Model: tools/double_accumulation_115.py. Tests:
tests/test_double_accumulation_115.py (12 tests, run with plain python3;
pytest is not installed on this VM).

## Windows (all whole-function, verbatim excerpts in excerpts/)

- Main 0x5f6c750..0x5f6cb28 (984 bytes, FDE file offset 0x1004ea4, length
  field 0x48, CIE at .eh_frame start, augmentation "zR", no LSDA field).
- Helper 0x5f6b720..0x5f6b736 (22 bytes, FDE 0x1004c8c, length field 0x10).
  Returns 0 when obj+0xa90 is set, else signed32(obj+0x10) - 2.
- Index leaf 0x5f6c740..0x5f6c750 (16 bytes, FDE 0x1004e90, length field
  0x10). Returns [[obj+0x18] + level * 8] with level sign-extended.

Census (whole-file scan, reproduced by census.py): main 0 direct calls,
exactly 1 tail jump (site 0x5f7e6de, site only), no stored qword, no
RELATIVE addend (virtual-dispatch shape); helper exactly 4 direct calls
(this pass's site 0x5f6c859 plus 0x5dbd78d, 0x5f7e45e, 0x5f7e5a7, sites
only), 0 tail jumps; leaf exactly 11 direct calls (this pass's site
0x5f6c88e, the #2322 scanner site 0x5d52c06, plus 0x5dc1201, 0x5dc1ef0,
0x5dc2114, 0x5f7e739, 0x5f7e764, 0x5f7e78c, 0x5f7e7a0, 0x5f7e9ad,
0x5f7eb12, sites only), 0 tail jumps. No window address appears as a
stored 8-byte qword or as a RELATIVE addend.

## Semantics, stated literally

Object fields: obj+0xa90 flag byte; obj+0xa98 base pointer of the 24-byte
group records (element-pointer begin, element-pointer end, third qword
never read); obj+0x10 signed 32-bit group count; obj+0xaf0 signed 32-bit
starting level; obj+0x18 index-array base pointer; obj+0xfc8 cached total
qword. Second argument fields: arg2+0x70 signed 32-bit count, arg2+0xa0
threshold qword. Each group element is a pointer to a record; the summed
field is the qword at element + 0x10. All sums wrap modulo 2**64. The
binary's SIMD pair loop is an implementation detail: addition modulo 2**64
commutes, so the plain wrapping sum equals it.

1. Flag set (obj+0xa90 != 0): cache = 0, return. This is the only
   early-return besides the loop gate.
2. Baseline: total = wrapping sum of group 0's element fields; N = the
   element count of group 0 (from its begin/end pointers). When arg2+0x70
   > N (signed 32-bit): if total >= arg2+0xa0 (unsigned) the pass
   proceeds with its flag live; otherwise the flag goes dead and total
   becomes 0. Otherwise the pass proceeds with the flag live.
3. cache = total. level starts at obj+0xaf0. The loop head returns when
   level > helper(obj) (signed 32-bit), i.e. while level <= count - 2
   when the flag is clear.
4. Each iteration: acc = previous group sum + remainder (wrapping). When
   the previous group sum is 0, the current group's sum is computed first
   and acc = remainder + that sum. Note the consequence on the first
   iteration: acc = total + group(level0) sum, and when level0 is 0 the
   group 0 sum is counted twice (once in total, once here) — that is what
   the instructions do, and the model reproduces it.
5. When the current level still equals obj+0xaf0 and the flag is live,
   the current group sum is added to the cache. Since level only
   increments, this fires at most once, on the first iteration.
6. index = index_leaf(level) (the old level, before incrementing).
   Level then increments by one (signed 32-bit wrapping).
   - index >= acc (unsigned): group sum and remainder reset to 0.
   - index < acc (unsigned): remainder = acc - index, group sum resets
     to 0, and when count > new level (signed) the new group's sum g is
     computed; when g != 0, cache += unsigned_double_to_int64(
     (g / acc + 1.0) * remainder), where each operand is converted from
     unsigned 64-bit to double exactly as the binary does (the shift/or/
     double sequence for values with the high bit set) and the result
     uses the binary's 2**63 bias conversion (subtract 2**63, convert
     with truncation, xor the sign bit when the value is >= 2**63).
7. The function returns void; the epilogue register value is not part of
   the pinned contract.

Rodata: 0x4592b0 holds the double 1.0; 0x459360 holds the double 2**63.

## Observations kept separate from inference

- Observed: the double-math block is reached only when index < acc, so
  acc > 0 there in every reachable execution except a wrapping case
  (remainder + group sum wrapping to exactly 0), which then cannot take
  the index < acc branch (no unsigned value is below 0). The divide-by-
  zero arm (acc == 0 in the double-math block) is therefore unreachable
  in the native code; the model still implements the IEEE result for it
  defensively but no test claims it end to end.
- Observed: the bytes at 0x5f6cb28 and after (an operator-delete call
  sequence) lie outside this function's FDE range (which ends at
  0x5f6cb28) and are not modelled here.
- Inferred name: "double-accumulation pass" describes the cache update
  rule (integer group sums plus one double-weighted term per qualifying
  level); the binary carries no name for it.
- Unknown: what the caller at the tail-jump site 0x5f7e6de does with the
  cache afterwards; the caller's other consumers of obj+0xfc8 are outside
  this work item.

## How the evidence was produced

Excerpts are verbatim objdump output, produced from the clone root with:

    objdump -d --start-address=0x5f6c750 --stop-address=0x5f6cb28 work/hl-node-115.bin
    objdump -d --start-address=0x5f6b720 --stop-address=0x5f6b736 work/hl-node-115.bin
    objdump -d --start-address=0x5f6c740 --stop-address=0x5f6c750 work/hl-node-115.bin

(or run export_excerpts.py). Instruction mnemonics such as `endbr64`,
`paddq` and `cvttsd2si` are genuine instructions present in the target
binary, not placeholders: verify.py re-checks three gate instructions and
three extra instructions byte-for-byte against a fresh objdump run and
against the raw binary bytes at file offset (displayed address - 0x1000).
The packet JSON (records.json) holds semantic records only; instruction-
level detail lives only in the verbatim excerpt text files. verify.py
(committed in this packet) re-runs every check: binary digest, provenance
binding, manifest, excerpt regeneration, instruction bytes, frames,
census and the model tests.

## Environment limits, stated honestly

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java. `make doctor`
fails on missing providers (pre-existing); `make verify` /
`make catalogue-check` fail on the LFS-pointer artifact here (pre-existing).
This packet binds instead to the materialized work/hl-node-115.bin whose
hash matches provenance/artifacts.json exactly. The pytest-style test file
ran under plain python3 via its `__main__` runner because pytest is not
installed here.
