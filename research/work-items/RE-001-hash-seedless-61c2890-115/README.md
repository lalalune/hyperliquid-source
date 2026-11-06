# RE-001: map node #115 seedless hash-long body (0x61c2890)

Task: RE-001 (#115 function map). Bounded question: what does the
1053-byte function at 0x61c2890 — the body the with-seed
hash-long body at 0x61c2cb0 tail-jumps to when its seed is zero,
left by contract only in the packet that pinned that body
(RE-001-hash-long-seed-61c2cb0-115) — compute, end to end: its
accumulator init, its stripe schedule over full blocks and the
tail, its scramble, its final stripe, and its one call?

- Component: node #115 seedless hash-long body (lengths 241+).
  One whole function, extracted from the digest-verified work
  binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x61c2890..0x61c2cad` (1053 bytes; FDE .eh_frame offset
  0x376d60, length 0x18, CIE 0, no LSDA).
- Signature: hash(data=rdi, length=rsi) -> rax. The third
  argument register is never read: the with-seed parent enters
  with the seed it just tested still in place (zero on that
  path), and the sibling entry enters with its own third
  argument in place; the value cannot affect the result.
- Claim status: observation for the window bounds, the two
  entry tail jumps with their gates (the parent's seed test at
  0x61c2cd0 and canary-verified exit jump at 0x61c2cf3; the
  sibling entry's length compare at 0x61c3a88 and its jump at
  0x61c3b50), the accumulator init ladder, the block loop and
  its scramble, the remainder stripe count and schedule, the
  final stripe's offset-121 secret window, the merge call and
  its argument setup, and the caller census; inference for the
  names "data" and "length" (they describe the observed roles)
  and for the hash-family reading of the parts; unresolved for
  the items listed in records.json (the sibling entry body's
  own arms, the exact source spelling, the remainder-count
  form).
- Semantics in one paragraph: all arithmetic is mod 2^64.
  Eight accumulators start at the prime ladder [PRIME32_3,
  PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4, PRIME32_2,
  PRIME64_5, PRIME32_1]. A stripe step over 64 data bytes, with
  the secret window at offset s, adds per qword lane
  data + lo32(x) * hi32(x) with x = data ^ SECRET[s + lane]
  into the accumulators. Full 1024-byte blocks run 16 stripes
  with the window sliding +8 per stripe, then scramble every
  accumulator: acc = (acc ^ (acc >> 47) ^ SECRET[128 + i]) *
  PRIME32_1, keyed by the secret's last 64 bytes. The tail runs
  (length >> 6) & 0xf further stripes from a reset window, and
  — only when length & 63 != 0 — one final stripe over the
  last 64 bytes with the window at offset 121. The body then
  calls the merge routine at 0x61c27f0 once with (accumulator
  array, secret + 11, length * PRIME64_1) and returns its
  result; the merge body is pinned by its own packet (PR
  #3533), and this packet pins the call site and the argument
  setup from this side. The constants, offsets and formulas
  are pinned per-part in records.json and in the model
  docstring.
- Note on evidence text: the raw disassembly excerpt is
  verbatim objdump output. Instruction mnemonics appearing in
  it are genuine instructions present in the target binary, not
  placeholders; the packet checker re-verifies sampled
  instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR title snapshot of 875 PRs, a
  repository search for 61c2890 in all notations, and the file
  lists of all 106 open dd12m54 PRs — no semantics pin; the
  RE-002 vendor census registers the window as
  XXPH3_hashLong_64b_defaultSecret, an identity only). The
  with-seed packet named this body as its seed-zero delegation
  target by contract; the merge packet pinned the merge call's
  geometry from the callee side. This packet resolves the
  seedless half of the 241+ arm and claims nothing about the
  sibling entry body beyond its jump site and its length gate.
- Evidence format: the packet JSON holds semantic records
  only — the accumulator structure, the stripe schedule, the
  secret offsets, the entry paths and the census.
  Instruction-level detail lives only in the verbatim
  whole-function excerpt. The verify script and the excerpt
  generator are committed in the packet, so the checker behind
  "ALL CHECKS PASSED" is visible in the diff.
- Verification beyond the packet checker: differential.py in
  this packet runs the window's real bytes under Unicorn —
  with the merge routine's real bytes behind the call and the
  stack canary emulated — and compares rax against the model
  on 816 cases (every length 241..600, structured payloads at
  all structural boundaries including the length % 64 == 0
  lengths, block and scramble boundaries up to 8192 bytes, one
  payload under four third-register values, and 300 random
  cases): 0 mismatches, the 64 accumulator bytes left in the
  stack frame identical to the model's in every case, the
  input buffer byte-identical, the callee-saved registers
  preserved, and every memory read inside [data, data+length),
  the secret table, the .rodata constant region, the stack or
  the canary page. It needs a python with the unicorn package,
  so it is run and recorded by the packet author, not by
  verify.py.
- Environment limits (stated honestly): no cargo/rustc, no
  Ghidra/Java on this VM, so no Rust reconstruction; the model
  and its tests are Python only and were run under plain
  python3 (pytest is not installed on this VM). Lengths below
  241 are not claimed: neither entry reaches this body with
  them, and this model documents the contract range only.
