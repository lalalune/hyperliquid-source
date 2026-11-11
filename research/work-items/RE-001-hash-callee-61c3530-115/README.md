# RE-001: map node #115 hash callee (0x61c3530)

Task: RE-001 (#115 function map). Bounded question: what does the
877-byte hash function at 0x61c3530 — cited by contract only by two
merged packets (RE-001-value-resolve-store-115 and
RE-001-protection-info-validate-115), and called directly from 108
sites — compute for each input length, and where does it hand off
the lengths it does not finish itself?

- Component: node #115 hash callee. One whole function, extracted
  from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x61c3530..0x61c389d` (877 bytes; FDE .eh_frame offset 0x376de0,
  length 0x38, CIE 0, no LSDA).
- Signature (observed at the two citing packets' call sites and
  confirmed at all 108 census sites): hash(data=rdi, length=rsi,
  seed=rdx) -> rax. The input is read, never written; there are no
  stores, no calls and no other side effects in the window, and
  the callee-saved registers are preserved.
- Claim status: observation for the window bounds, the length
  dispatch (0 / 1..3 / 4..8 / 9..16 / the accumulator bands
  17..32, 33..64, 65..96, 97..128), every lane constant, the
  multiply-fold primitive, the shared final mix, the two
  delegation tail jumps with their exact length bounds
  (129..240 -> 0x61c3230, 241+ -> 0x61c2cb0), and the caller
  census; inference for the names "data", "length" and "seed"
  (they describe the observed roles) and for the wyhash-family
  resemblance noted in records.json; unresolved for the items
  listed in records.json (the two delegation targets' bodies, the
  exact source spelling, the callers' seed choices).
- Semantics in one paragraph: all arithmetic is mod 2^64. A lane
  pair contributes fold(x, y) = lo(x*y) ^ hi(x*y) with
  x = (K1 + seed) ^ rd64(first) and y = (K2 - seed) ^ rd64(second).
  Length 0 returns fold(C_A + seed, P2) without dereferencing the
  data pointer. Lengths 1..3 pack first/middle/last bytes and the
  length into 32 bits and run one prime multiply. Lengths 4..8
  combine two overlapping dword reads. Lengths 9..16 run one lane
  pair over the two overlapping qword reads at the ends. Lengths
  17..128 accumulate P1 * length plus one 32-byte band sum
  (two lane pairs) per band the length reaches — band B from 33,
  band A from 65, band D from 97 — plus the final two lane pairs
  at the input's head and tail. Every in-window arm ends in the
  same final mix: y = x ^ (x >> 37); y *= 0x165667b19e3779f9;
  y ^ (y >> 32). The constants, offsets and arm formulas are
  pinned per-arm in records.json and in the model docstring.
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR title snapshot of 784 PRs plus a
  repository search for 61c3530 in all notations, no hit). The
  two citing packets name this body as their first unknown; this
  packet resolves exactly that unknown and claims nothing about
  the callers beyond the census. The delegation targets
  0x61c3230 and 0x61c2cb0 are cited by contract only here, the
  same boundary the citing packets kept for this function.
- Evidence format: the packet JSON holds semantic records only —
  the length arms, the lane constants, the delegation and the
  census. Instruction-level detail lives only in the verbatim
  whole-function excerpt. The verify script and the excerpt
  generator are committed in the packet, so the checker behind
  "ALL CHECKS PASSED" is visible in the diff.
- Verification beyond the packet checker: differential.py in
  this packet runs the window's real bytes under Unicorn and
  compares rax against the model on 1053 cases (every length
  0..128 under two seeds, structured payloads at all band
  boundaries under six seeds, 300 random cases, the four fold
  seeds used by the citing packets, a length-0 call with a null
  data pointer, and 10 delegation cases landing on marker stubs
  at the two targets): 0 mismatches, the input buffer
  byte-identical and the callee-saved registers preserved in
  every case. It needs a python with the unicorn package, so it
  is run and recorded by the packet author, not by verify.py.
- Environment limits (stated honestly): no cargo/rustc, no
  Ghidra/Java on this VM, so no Rust reconstruction; the model
  and its tests are Python only and were run under plain
  python3 (pytest is not installed on this VM). The delegation
  targets' bodies are not modelled: the model raises for
  lengths 129 and above and names the target instead.
