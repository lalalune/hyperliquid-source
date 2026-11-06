# RE-001: map node #115 hash entry (0x61c34a0)

Task: RE-001 (#115 function map). Bounded question: what does the
133-byte function at 0x61c34a0 — cited by contract only by three
merged packets (RE-001-hash-find-insert-115 lists "the hash
callee 0x61c34a0's body" first among its unknowns, and
RE-014-batch-lookup-115 and RE-014-memtable-iterator-seek-gate-115
call it and record only its size and seeds) — compute for each input length, and
who calls it across the whole binary?

- Component: node #115 hash entry. One whole function, extracted
  from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x61c34a0..0x61c3525` (133 bytes; FDE .eh_frame offset
  0x376dcc, length 0x10, CIE 0, no LSDA, no CFA instructions
  beyond padding nops — the body builds no stack frame).
- Signature (observed at the two citing packets' documented call
  sites and consistent with the body's register use):
  hash(data=rdi, length=rsi, seed=edx) -> eax. The input is
  read, never written; there are no stores, no calls and no
  other side effects in the window.
- Claim status: observation for the window bounds, the initial
  fold, the word step and its loop bounds, the tail fold with
  its sign-extended bytes, the final mix and the one remainder
  class that skips it, and the caller census; inference for the
  names "data", "length" and "seed" (they describe the observed
  roles) and for the MurmurHash-family resemblance noted in
  records.json (the multiplier 0xc6a4a793); unresolved for the
  items listed in records.json (the source spelling beyond the
  RE-002 census identity, the other call sites' seeds, lengths
  >= 2^32 at the differential level, the #94 byte-identity
  claim).
- Semantics in one paragraph: all arithmetic is 32-bit, mod
  2^32, with the single multiplier M = 0xc6a4a793. The
  accumulator starts at h = (uint32(length) * M) ^ seed (the
  initial imul reads %esi, the low half of the length; the end
  pointer uses the full length). For each little-endian 4-byte
  word w of the input, in order: h += w; t = h * M;
  h = t ^ (t >> 16). The tail (length mod 4 bytes) then splits
  by remainder: remainder 0 returns h as it stands, with no
  final mix (so length 0 returns the seed itself); otherwise
  the tail bytes are sign-extended (movsbl) and added at their
  positions — tail[2] << 16, then tail[1] << 8, then tail[0] —
  and one final mix runs: t = h * M; result = t ^ (t >> 24).
  The result is the 32-bit value in %eax, zero-extended into
  %rax.
- Census: 26 direct call sites in 19 containing FDEs, each
  confirmed by linear disassembly of its containing FDE from
  the FDE start; no tail jumps, no qword references and no
  RELATIVE relocation slots target the window, and the 15
  int3 bytes before it rule out a fall-through entry. Two
  sites are documented by the citing packets: 0x5f0e695 (seed
  0x18d) and 0x5f0da73 (seed 0xbc9f1d34).
- Note on evidence text: the raw disassembly excerpt is
  verbatim objdump output. Instruction mnemonics appearing in
  it (including `endbr64` at the window entry) are genuine
  instructions present in the target binary, not placeholders;
  the packet checker verifies sampled instructions
  byte-for-byte against both a fresh objdump run and the raw
  binary.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x61c34a0 --stop-address=0x61c3525 work/hl-node-115.bin
objdump --dwarf=frames work/hl-node-115.bin   # FDE block in frames.txt
```

## Verification

- `verify.py` (this packet): digest, manifest, excerpt and
  frames regeneration, sampled-instruction byte checks, census
  reproduction, and the model test file — ALL CHECKS PASSED.
- `differential.py`: the window's real bytes under Unicorn vs
  the model in tools/hash_entry_61c34a0_115.py — 980 cases,
  0 mismatches (every length 0..64 under six seeds, structured
  payloads per remainder class including high-bit tail bytes,
  larger lengths, 300 fuzz cases; per case it also checks
  rax zero-extension, input immutability, callee-saved
  preservation, and that every read lands inside the input or
  the stack).
