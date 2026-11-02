# RE-001: map node #115 hash-bucket projection (0x5f099b0)

Task: RE-001 (#115 function map). Bounded question: what does the
function at 0x5f099b0 do end to end — how does it turn a key and a
table span into the address of one 56-byte table entry?

- Component: node #115 hash-bucket projection. One whole function,
  extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x5f099b0..0x5f09a42` (146 bytes; FDE .eh_frame offset 0x358a34,
  length 0x24, CIE 0, no LSDA asserted).
- Claim status: observation for the window bounds, the span fields
  and shift, the scale constant and its inverse identity, the hash
  call site and its arguments, the widening multiply and its closed
  form, the 56-byte stride result, and the caller census; inference
  for the names "base", "end" and "key" (they describe the observed
  roles, not proven source names); unresolved for the items listed
  in records.json (the hash callee 0x61c38a0's body, the five
  0x5f0cxxx callers' containing functions, the whole-entry-span
  guarantee for all callers, the exact C++ spelling).
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR snapshot plus a repository search
  for 5f099b0, no hit). It is the bucket lookup the two neighbouring
  record-store wrappers use on their tag-match paths: the 0x5f0f3d0
  wrapper calls it at 0x5f0f6bd and the 0x5f0f930 wrapper at
  0x5f0fbdf, each immediately after building the key slice record
  whose entry address this function returns. It is distinct from
  the stride-56 span projection at 0x4561f70 in another contributor's
  open PR, which is a different window address.
- The key observation: the scale constant 0x6db6db6db6db6db7 is the
  modular inverse of 7 modulo 2**64, so multiplying the span's
  8-byte-unit count by it divides a whole-entry span by 7 exactly:
  a span of 56 * k bytes yields the entry count k. The bucket is
  then the high 64 bits of hash * k — Fibonacci-style hashing —
  and the result is base + 56 * bucket. The window itself never
  checks that the span is a whole number of entries; that
  guarantee belongs to the callers.
- Verification: run the packet checker from the repository root:
  `python3 research/work-items/RE-001-hash-bucket-projection-115/verify.py`
  (digest, provenance, manifest, excerpt regeneration, sampled +
  3 self-check instructions byte-for-byte vs fresh objdump and raw
  binary, frames, census, model tests).
