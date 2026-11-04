# RE-001: map node #115 ProtectionInfo validation (0x5f09b10)

Task: RE-001 (#115 function map). Bounded question: what does the
function at 0x5f09b10 do end to end — how does it validate a
two-field length-prefixed record and its ProtectionInfo fold, and
what does it report on each failure?

- Component: node #115 ProtectionInfo validation. One whole function,
  extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x5f09b10..0x5f09e84` (932 bytes; FDE .eh_frame offset 0x358aa0,
  length 0x48, CIE 0, no LSDA asserted).
- Claim status: observation for the window bounds, the length-prefix
  parses and their bounds rules, the trailer position, the four hash
  call sites with their seeds and inputs, the fold equality, the
  seven error messages (quoted verbatim from .rodata, with addresses
  and lengths), the success store ranges, and the caller census;
  inference for the names "key", "value", "trailer", "protection"
  and "status" (they describe the observed roles and the messages'
  own words); unresolved for the items listed in records.json (the
  hash callee 0x61c3530's body, the varint callee 0x61bd4f0's body,
  the exact status bytes the report callee writes, the exact C++
  spelling).
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR snapshot plus a repository search
  for 5f09b10, no hit). It is the consumer-side companion of the
  neighbouring value resolve-and-store packet (#2084, window
  0x5f09e90): the same four hash seeds appear here in a validation
  fold instead of a construction fold, and its three direct callers
  are the large insert function at 0x5f0e890 (site 0x5f0ea79) and
  the two wrappers at 0x5f0f3d0 (site 0x5f0f818) and 0x5f0f930
  (site 0x5f0fe35), which call it immediately after the
  resolve-and-store helper.
- The success store is recorded literally: a dword at status+0x00,
  a word at status+0x04 and a qword at status+0x08, so status bytes
  6..7 are never written by this window (the model preserves them).
