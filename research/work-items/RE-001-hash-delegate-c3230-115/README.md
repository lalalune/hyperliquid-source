# RE-001: map node #115 hash delegate (0x61c3230)

Task: RE-001 (#115 function map). Bounded question: what does the
609-byte function at 0x61c3230 — the body the hash callee at
0x61c3530 delegates lengths 129..240 to by tail jump, left by
contract only in the packet that pinned the callee
(RE-001-hash-callee-61c3530-115) — compute, end to end: its
accumulator structure, its stripe schedule, the exact secret
offsets it reads, and its second entry path?

- Component: node #115 hash delegate (lengths 129..240). One whole
  function, extracted from the digest-verified work binary
  (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x61c3230..0x61c3491` (609 bytes; FDE .eh_frame offset
  0x376da0, length 0x28, CIE 0, no LSDA).
- Signature: hash(data=rdi, length=rsi, seed=rdx) -> rax, the
  parent callee's own signature — both entries are tail jumps
  with the argument registers already in place. The input is
  read, never written; there are no stores but the saved-register
  pushes, no calls and no other side effects in the window, and
  the callee-saved registers are preserved.
- Claim status: observation for the window bounds, the two entry
  tail jumps with their gates (the parent's delegation at
  0x61c3750; a sibling hash body's seed-0 entry at 0x61c3a97),
  the accumulator structure (init, eight opening lane pairs, one
  intermediate avalanche, the middle loop, the final pair, the
  closing avalanche), every lane constant and secret offset, and
  the caller census; inference for the names "data", "length"
  and "seed" (they describe the observed roles) and for the
  wyhash-family resemblance noted in records.json; unresolved
  for the items listed in records.json (the sibling entry body's
  own arms, the second delegation target 0x61c2cb0, the exact
  source spelling, the source-level reason for the middle loop's
  +3 secret offset).
- Semantics in one paragraph: all arithmetic is mod 2^64. A lane
  pair contributes fold(x, y) = lo(x*y) ^ hi(x*y) with
  x = (K1 + seed) ^ rd64(first) and y = (K2 - seed) ^
  rd64(second), where K1/K2 are consecutive qwords of the
  192-byte secret table at 0x97df00 (the same table the parent
  cites). The accumulator starts at len * 0x9e3779b185ebca87 and
  absorbs eight opening lane pairs over data[0..128) (secret
  offsets 16*i, baked in as immediates). It is then avalanched
  once (y = x ^ (x >> 37); y *= 0x165667b19e3779f9;
  y ^ (y >> 32)). Lengths above 143 add the middle loop:
  nbRounds - 8 further pairs (nbRounds = len >> 4) over
  data + 128 + 16*k, with the secret read from memory at offset
  3 + 16*k — not the stripe-aligned offset. A final pair over
  data + len - 16 with the secret at offset 119 is added, and
  the result is avalanched again. The constants, offsets and
  formulas are pinned per-part in records.json and in the model
  docstring.
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it are
  genuine instructions present in the target binary, not
  placeholders; the packet checker re-verifies sampled
  instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR title snapshot of 828 PRs, a
  repository search for 61c3230 in all notations, and the file
  lists of all 101 open dd12m54 PRs — no semantics pin; the
  RE-002 vendor census registers the window as
  XXPH3_len_129to240_64b.constprop.0, an identity only). The
  parent packet named this body as one of its two remaining
  contract-only delegates; this packet resolves the 129..240
  half and claims nothing about the sibling entry body beyond
  its jump site, its length gate and its seed zeroing.
- Evidence format: the packet JSON holds semantic records only —
  the accumulator structure, the secret offsets, the entry paths
  and the census. Instruction-level detail lives only in the
  verbatim whole-function excerpt. The verify script and the
  excerpt generator are committed in the packet, so the checker
  behind "ALL CHECKS PASSED" is visible in the diff.
- Verification beyond the packet checker: differential.py in
  this packet runs the window's real bytes under Unicorn and
  compares rax against the model on 866 cases (every length
  129..240 under two seeds, structured payloads at all
  structural boundaries under six seeds, seed-0 cases, and 300
  random cases): 0 mismatches, the input buffer byte-identical,
  the callee-saved registers preserved, and every memory read
  inside [data, data+length), the secret table or the stack in
  every case. It needs a python with the unicorn package, so it
  is run and recorded by the packet author, not by verify.py.
- Environment limits (stated honestly): no cargo/rustc, no
  Ghidra/Java on this VM, so no Rust reconstruction; the model
  and its tests are Python only and were run under plain
  python3 (pytest is not installed on this VM). Lengths outside
  129..240 are not claimed: the parent never delegates them
  here, and the opening stripes read data[0..128)
  unconditionally, so the model documents the contract range
  only.
