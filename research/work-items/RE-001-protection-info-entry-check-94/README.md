# RE-001: map node #94 ProtectionInfo entry check (0x51694e0)

Task: RE-001 (#94 function map). Bounded question: how does node #94
verify a length-prefixed internal key plus its trailing value against a
caller-provided ProtectionInfo hash — what length gates run first, what
exactness rule binds the value to the buffer end, and what hash
combination must match?

- Component: node #94 ProtectionInfo entry check. One window, extracted
  from the digest-verified work binary (SHA-256
  `3b7179cd…c0459f`): `0x51694e0..0x5169854` (884 bytes, FDE
  0xf7d300, CIE 0xce1518, no LSDA). It is a neighbour of the memtable
  iterator family mapped in the #1984/#1985/#1989/#1991/#1994 packets
  and is reached by three direct calls (0x516e449, 0x516f1e8,
  0x516f805), not through a vtable slot.
- Claim status: observation for the window bounds, the argument roles,
  the two length-prefix parses, the minimum-length gate, the
  remaining-length gate, the entry/trailer split, the exact-value rule,
  the four hash seeds and their combination, the success zero record,
  the seven detail strings and the three call sites; inference for the
  names "ProtectionInfo entry check" and "value" (the detail string
  literally says "ProtectionInfo mismatch" and the value-length strings
  literally say "value length"); unresolved for the identity of the
  gate object (rsi) and of the object at its +0x10 field whose +0x28
  field sets the minimum length, the identity of the caller u64 at *r8
  beyond its role as the expected hash, and the internals of the hash
  function 0x5422f00 and the detail builder 0x542f040 (both used by
  contract, as in the neighbouring packets).
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers this
  window (checked this cycle: open-PR snapshot, no 0x51694e0 or
  protection-info title). The #1985 entry check (0x5167040) shares
  the length-prefix form, the same length-parse failure string, the
  same four hash seeds and the same detail-builder protocol, but it
  is a different function: it takes a width argument, compares width
  bytes of a stored checksum found after the suffix, and has no
  caller-hash argument, no minimum-length gate and no
  exact-value-to-end rule. This window has no width arms and no
  stored checksum in the buffer; the expected hash arrives through
  the r8 pointer instead.

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; frames.txt rows are verbatim from
  work/fde94/node-94-fde.tsv.
- Environment limits, stated honestly: `make doctor` reports
  analysis_ready false on this VM (no cargo/rustc, no git-lfs, no
  Ghidra/Java, no pinned REA package); the REA server path in
  AGENTS.md is therefore unavailable and this packet is grounded in
  objdump disassembly plus relocation and FDE records only. pytest
  is not installed, so the pytest-style test file runs under plain
  python3 via its `__main__` runner.

## Answer

`check(out, gate_object, buffer, buffer_length, expected_ptr) -> void`.
The out record is zeroed on success and carries an error detail on
failure (detail builder 0x542f040, constant argument 2, as pinned in
the neighbouring entry-check packet).

Length prefix (twice: internal key, then value). A first byte below
0x80 is the length and the payload starts one byte later; otherwise
the 32-bit varint helper 0x541cec0 decodes it (7-bit groups, shifts
0/7/14/21/28, a null return on running past the end or on a fifth
continuation byte). The helper's own disassembly was read to pin this
cap; its FDE row is in frames.txt.

Internal-key gates, in order:

1. Minimum length: L must be at least (u64 at [[gate_object + 0x10]
   + 0x28]) + 8, else detail "Internal key length too short".
2. Remaining length: the bytes after the length prefix must be at
   least L, else detail "Internal key length too long".
3. A length-prefix decode failure at either stage reports "Unable to
   parse internal key length" (first stage) or "Unable to parse value
   length" (second stage); an empty buffer fails at the first stage
   because the helper is entered with position == end.

Entry layout. The entry is the L bytes after the length prefix:
user key = entry[0:L-8]; trailer = entry[L-8:L] little-endian, low
byte = value type, next 7 bytes = 56-bit sequence (trailer >> 8).

Value exactness rule. The value starts after the entry end and has
its own length prefix. Its length must equal the bytes remaining to
the buffer end exactly: shorter reports "Value length too short",
longer reports "Value length too long". The value therefore always
runs to the buffer end; there is no stored checksum after it.

Hash check. With the hash function 0x5422f00 by contract:

- H1 = H(sequence as u64 little-endian, seed 0x77a00858ddd37f21)
- H2 = H(user key, seed 0)
- H3 = H(value, seed 0xd28aad72f49bd50b)
- H4 = H(value type as one byte, seed 0xa5155ae5e937aa16)

The code accumulates H1 ^ H2 ^ (*expected_ptr) ^ H3 and compares
H4 against that accumulator, which is algebraically the condition
*expected_ptr == H1 ^ H2 ^ H3 ^ H4. On equality the out record is
zeroed (code u32 at +0, sub u16 at +4, detail pointer at +8, all
zero; detail length/capacity slots untouched, as in the neighbouring
packet). On inequality the detail is "ProtectionInfo mismatch".

Caller census (per-byte e8/e9 scan of .text, whole-file qword
search, .rela.dyn parse — see census.py): three direct calls
(0x516e449, 0x516f1e8, 0x516f805), no tail jumps, no qword
references, no RELATIVE slot. The caller-side components owning
those sites are not identified here.
