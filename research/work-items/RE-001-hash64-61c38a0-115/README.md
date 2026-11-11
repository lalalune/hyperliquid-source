# RE-001: map node #115 Hash64 body (0x61c38a0)

Task: RE-001 (#115 function map). Bounded question: what does the
793-byte function at 0x61c38a0 — the hash callee the merged
bucket-projection packet (RE-001-hash-bucket-projection-115)
cited by contract only, calling it with (key pointer, key
length) at 0x5f099e7 — compute, end to end: its length arms,
its stripe schedule and secret offsets, its delegation exits,
and its full caller census?

- Component: node #115 Hash64 entry (lengths 0..128 inline,
  129+ delegated). One whole function, extracted from the
  digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x61c38a0..0x61c3bb9` (793 bytes; FDE .eh_frame offset
  0x376e1c, length 0x38, CIE 0, no LSDA asserted).
- Signature: hash(data=rdi, length=rsi) -> rax. There is no
  seed argument: every lane constant is baked in as an
  immediate. The input is read, never written; there are no
  stores at all, no calls, and no other side effects in the
  window, and the callee-saved registers are preserved (the
  banded arms push and pop r15, r14, r12).
- Claim status: observation for the window bounds, the length
  dispatch and every arm's formula (the empty constant, the
  1..3 combined-word arm, the 4..8 widened arm, the 9..16 pair
  arm, and the four stripe bands with their secret offsets),
  the two delegation exits with their gates and register
  contracts, the shared-avalanche structure, and the caller
  census; inference for the names "data" and "length" (they
  describe the observed roles); unresolved for the items
  listed in records.json (the two delegation targets' bodies,
  the adapter stub's own body, the other callers' identities,
  the exact source spelling, the empty-input constant's
  derivation).
- Semantics in one paragraph: all arithmetic is mod 2^64.
  Length selects the arm. Empty input returns the constant
  0x5342c3010fe1dd04 untouched. Lengths 1..3 pack
  data[0] | data[len>>1]<<8 | data[len-1]<<16 | len<<24, xor
  the low half of secret qword 0, multiply by PRIME64_1 and
  avalanche. Lengths 4..8 widen the two end dwords into one
  qword, xor secret qword 0, then h ^= h>>51, h *= 0x9e3779b1,
  h += len, h ^= h>>47, and avalanche(h * PRIME64_2). Lengths
  9..16 fold one lane pair (secret 0) plus len into a single
  multiply fold and avalanche. Lengths 17..128 start from
  acc = len * PRIME64_1 and add lane-pair folds
  fold(x, y) = lo(x*y) ^ hi(x*y) over pairs read at fixed and
  end-relative offsets, each pair xoring consecutive qwords
  of the 192-byte secret table at 0x97df00 (as immediates):
  always the first pair (secret 0) and the last pair
  (secret 16), plus one stripe block per band — (data+16,
  secret 32) and (data+len-32, secret 48) from length 33,
  (data+32, secret 64) and (data+len-48, secret 80) from 65,
  (data+48, secret 96) and (data+len-64, secret 112) from
  97 — and avalanche once at the end. avalanche(x) is
  y = x ^ (x >> 37); y *= 0x165667b19e3779f9; y ^ (y >> 32).
  Lengths 129..240 zero edx and tail-jump to the delegate at
  0x61c3230; lengths 241+ tail-jump to the seedless body at
  0x61c2890. Both targets are cited by contract only.
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it
  (including `endbr64` at the window entry) are genuine
  instructions present in the target binary, not placeholders;
  the packet checker re-verifies sampled instructions
  byte-for-byte against a fresh objdump run and the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR title snapshot of 874 PRs, a
  repository search for 61c38a0 and for Hash64 in all states,
  the changed-file lists of all 196 open dd12m54 PRs, the
  owners.json pins and the merged work-items — the only merged
  mention is the citing packet itself). It is the last
  contract-only body of the RE-001 hash cluster the recent
  packets left open: the parent callee at 0x61c3530 (PR #3486)
  is this body's neighbour, its 129..240 delegate at
  0x61c3230 (PR #3489) is entered from inside this window at
  0x61c3a97 with the seed zeroed, and the seedless target at
  0x61c2890 is the body PR #3510's packet cites. The RE-002
  vendor census registers the window as librocksdb-sys
  0.11.0+8.1.1 `rocksdb::Hash64(const char*, size_t)` — an
  identity only; this packet pins the semantics.
- Evidence format: the packet JSON holds semantic records only —
  the length arms, the secret offsets, the delegation contracts
  and the census. Instruction-level detail lives only in the
  verbatim whole-function excerpt. The verify script and the
  excerpt generator are committed in the packet, so the checker
  behind "ALL CHECKS PASSED" is visible in the diff.
- Verification beyond the packet checker: differential.py in
  this packet runs the window's real bytes under Unicorn and
  compares rax against the model on 1106 inline cases (every
  length 0..128 under four structured payloads and two random
  ones, high-bit payloads at the band edges, and 300 fuzz
  cases): 0 mismatches, the input buffer byte-identical, the
  callee-saved registers preserved, rsp balanced, and every
  memory read inside [data, data+len) or the stack in every
  case. Eight page-edge cases place the largest input of each
  band flush against the end of a mapped page, so any read
  past the input would have faulted; none did. Eleven
  delegation cases stop at the two tail-jump targets and check
  the register contract from this side (delegate: rdx zeroed;
  seedless: rdx untouched; rdi/rsi unchanged in both). It
  needs a python with the unicorn package, so it is run and
  recorded by the packet author, not by verify.py. One model
  error was caught and fixed by this differential before
  submission: the end-64 stripe pair's two lane constants
  (secret offsets 112 and 120) were first paired with the
  wrong data words — fold(x, y) is symmetric in its two lane
  values, but re-pairing the constants with different data
  words changes the product, and lengths 97..128 exposed it.
- Environment limits (stated honestly): no cargo/rustc, no
  Ghidra/Java on this VM, so no Rust reconstruction; the model
  and its tests are Python only and were run under plain
  python3 (pytest is not installed on this VM). Lengths above
  128 are not claimed beyond the delegation contracts: the
  body never finishes them, and their target bodies belong to
  their own packets.
