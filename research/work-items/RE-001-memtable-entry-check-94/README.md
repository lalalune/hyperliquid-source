# RE-001: map node #94 memtable entry check (0x5167040)

Task: RE-001 (#94 function map). Bounded question: how does the
routine the MemtableIterator refresh handlers call as their reader
decide whether a length-prefixed memtable entry is intact, and what
record does it write when it is not?

- Component: node #94 memtable entry check. One window, extracted
  from the digest-verified work binary (SHA-256
  `3b7179cd…c0459f`): `0x5167040..0x5167b9b` (2907 bytes, FDE
  0x1316e14, LSDA 0xbd8a59). The window is the reader the five
  refresh handlers mapped in #1984 call as
  `reader(record, buffer, tag_width, 0)`.
- Claim status: observation for the window bounds, the length-prefix
  parse, the trailer split, the suffix parse, the stored-checksum
  position, the width dispatch, the zero-record write set, the
  four-part hash chain and its seeds, the error strings, the
  mismatch-detail composition, the hex callee and the detail-builder
  record layout, and the caller census; inference for the names
  "memtable entry", "user key", "value type" and "seq" (the detail
  strings literally name the memtable entry, the user key and the
  sequence; the other names describe the observed field roles);
  unresolved for the hash callee's byte-exact values, truncated
  buffers (the binary performs no bounds check here), the dead jae
  edge in the suffix scan, and the roles of the three non-refresh
  caller functions.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at each window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers this
  window (checked this cycle: 67 open, no 0x5167040/memtable-entry
  title). The five refresh handlers (#1984) use this routine by
  contract only; this packet maps the routine itself. The WAL
  windows (#1969, #1966, #1964, #1958, #1948, #1982) map different
  functions.

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

`check(buffer, width, flag)` writes a record and returns void. The
record layout used by the handlers: code u32 at +0, sub u16 at +4,
detail string at +8.

### Entry parse

- `width == 0` returns the zero record before reading the buffer.
- Length prefix: first byte below `0x80` is the length and the
  entry starts at `buffer+1`; otherwise a bounded LEB128 varint
  (limit `buffer+5`, callee 0x541cec0) is decoded at `buffer` and
  the entry starts past it. Decode failure writes error
  `Unable to parse internal key length` (code 2).
- Length 7 or less writes error `Memtable entry internal key
  length too short.` (code 2).
- Entry layout: user key `entry[0:len-8]`; trailer
  `entry[len-8:len]` little-endian, where the low byte is the value
  type and the next 7 bytes are the 56-bit sequence.
- Suffix: the byte at `entry_end` is the suffix length when below
  `0x80` (suffix starts one byte later); otherwise a bounded
  LEB128 varint (limit `entry_end+5`) is decoded there. Decode
  failure writes error `Unable to parse internal key value`.
- Stored checksum: `width` bytes at `suffix_start + suffix_len`,
  little-endian.

### Hash chain and width dispatch

- Combined hash: `H(user_key, 0) ^ H(suffix, 0xd28aad72f49bd50b)
  ^ H(bytes([value_type]), 0xa5155ae5e937aa16) ^
  H(seq_as_u64_le, 0x77a00858ddd37f21)`, where `H` is libstdc++
  `std::_Hash_bytes` (0x5422f00, by contract).
- Widths 1, 2, 4, 8 compare the low 1, 2, 4, 8 bytes of the chain
  against the stored checksum. Widths 3, 5, 6, 7 skip the
  comparison and return the zero record after parsing and hashing.
- Match: zero record (code 0, sub 0, detail pointer 0). The
  binary writes only code, sub and the detail pointer on this
  path; the detail length/capacity slots are left untouched, so
  callers pass a zero-initialised record.
- Mismatch, flag 0: detail is exactly `Corrupted memtable entry,
  per key-value checksum verification failed.` (69 bytes, built
  from four rodata chunks plus ` failed.`).
- Mismatch, flag nonzero: the same base plus `Unrecognized value
  type: <type>. `, `User key: <lowercase hex of user key>. ` and
  `seq: <seq>. `. The hex piece is the 0x5427800 callee; the
  detail builder 0x542f040 writes record bytes `[2, 0, 0, 0, 0]`
  and a heap copy of the detail (its auxiliary-append arm is dead
  for this caller: aux length 0).
- Exception cleanup (0x5166fd4..0x5167040 and the landing pads at
  0x5167b23..0x5167b9b) only disposes temporaries and resumes
  unwinding; it is not normal-path behaviour.

### Census

8 direct call sites, 0 tail jumps, 0 qword references, 0
RELATIVE slots: 0x5167c1c (in 0x5167ba0), 0x5167d6c (in
0x5167cf0), 0x5167efd (in 0x5167e40), 0x516808d (in 0x5167fd0),
0x5168537 (in 0x51684d0) — the five refresh handlers of #1984 —
plus 0x516833f (in 0x5168160), 0x5168ef5 (in 0x5168a20) and
0x516b2ba (in 0x516b130), whose enclosing functions' roles are
not pinned here.
