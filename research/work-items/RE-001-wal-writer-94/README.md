# RE-001: map node #94 WAL writer AddRecord 0x5163730 with its fragment emitter 0x5163550 and compression-type record 0x5163ba0

Task: RE-001 (#94 function map). Bounded question: how does the node #94
WAL writer turn one input record into physical fragments — which fragment
types, which header bytes, which block rules — and how does it emit the
SetCompressionType record and install the compressor?

- Component: node #94 WAL writer, windows `0x5163730..0x5163b5f`
  (AddRecord, 1071 bytes), `0x5163550..0x51636f6` (EmitFragment, 422
  bytes), `0x5163ba0..0x5163dec` (EmitCompressionTypeRecord, 588 bytes),
  plus the AddRecord cleanup stub `0x5163b60..0x5163b94` and the setup
  cleanup stub `0x5163dec..0x5163e18`. The append (0x52b4050), the
  completion step (0x52b13f0), the compressor virtuals (+0x18 begin,
  +0x10 step), the factory (0x54215e0) and the CRC pair (0x5421fc0,
  0x5421fd0) are used by contract only; their internals are not pinned
  here.
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the window bounds, the writer field
  offsets, the fragment type derivation, the header layout, the block
  and trailer rules, the append call sequence, the error records and
  their messages, the census and the canary slot; inference for the
  log-number field name, the type_crc construction (crc32c of the single
  type byte), the compressor's internal consumption state, and the
  result-record field semantics beyond the observed values; unresolved
  for the append internals, the completion-step internals, the factory
  internals, the aux integer role, and the setters of the writer flags
  outside this cluster (see records.json).
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at each window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Relationship to earlier work: PR #1848 pinned the same 7 and 11-byte
  header forms and the same CRC mask rule on the reader side; PRs #1860
  and #1948 pinned the same fragment type codes 1 through 9 on the
  reader side. This PR is the writer direction of that grammar, not a
  re-submission of any of those windows. The WAL reader constructor in
  PR #1865 is a different object in the same neighborhood. No open
  WalkCrypto PR covers the writer windows (checked this cycle).

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; `objdump --dwarf=frames` is not used
  for frames.txt (rows are verbatim from work/fde94/node-94-fde.tsv).

## Answer

`add_record(writer, data)` returns a 16-byte result record (code u32 at
+0, u16 at +4, message pointer at +8; byte +0 nonzero is terminal).
Without a compressor, fragments come from the input slice directly; with
one, the compressor's begin virtual (+0x18) runs once, then each step
virtual (+0x10) fills the scratch buffer and returns the output length
plus a status (negative = error, 0 = final chunk, positive = more
chunks). A step call happens on the first iteration and whenever the
previous output is exhausted, so the data-pointer advance survives
across fragments of one chunk.

Blocks are 0x8000 bytes. The header is 7 bytes, or 11 for recyclable
records: masked CRC u32, length u16, type u8, plus the log number u32
for recyclable types. The CRC is mask(combine(type_crc[type],
crc32c(payload), len(payload))), with mask(x) = ror32(x, 15) +
0xa282ead8 — the inverse of the reader-side unmask rule from #1848.
When the block remainder is below the header size, a zero trailer
(source 0x7ee187, at most 10 bytes) pads the block and the offset
resets to 0.

Fragment types: full 1, first 2, middle 3, last 4, plus 4 for recyclable
(5..8). A fragment is full exactly when it consumes the chunk, the
chunk status is 0 (final) and the first-fragment flag is set; last when
it consumes the chunk, the status is 0 and the flag is clear; otherwise
first when the flag is set, middle when it is clear. The flag is set at
entry and cleared after each emitted fragment.

Each fragment is emitted by 0x5163550: build the header, append the
header slice, and — unless that append's result byte +0 is nonzero —
append the data slice; the block offset always advances by header plus
payload. A negative compressor status builds the record {code 5, u16
at +4 = 1, "Unexpected WAL compression error"} and returns it directly.
At the end, when the finalize flag (+0x44) is clear, the completion
step (0x52b13f0) runs and its result replaces the loop result.

`emit_compression_record(writer)` returns empty when the compression
type byte (+0x45) is 0. Otherwise it emits a type 9 fragment whose
payload is that byte as a 4-byte little-endian value, with aux 4. A
terminal helper result clears the type byte and returns. Otherwise the
completion step runs when the finalize flag is clear, then the
compressor is created via the factory (0x54215e0) and a scratch buffer
of block size minus header size (0x7ff9, or 0x7ff5 when recyclable) is
allocated.

## Verification

- `python3 tests/test_wal_writer.py`: 23 tests pass (fragment types,
  both header forms, CRC mask/combine roundtrip against the reader
  rule, block and trailer rules, both compressor paths, both error
  records, the compression-type emission, corruption controls).
  pytest is not installed on this VM, so the pytest-compatible file
  ran under plain python3 via its `__main__` runner.
- `python3 research/work-items/RE-001-wal-writer-94/verify.py`: ALL
  CHECKS PASSED (digest, manifest, excerpt regeneration, 3 sampled
  instructions byte-for-byte against the fresh objdump run and the raw
  binary, rodata strings, frames, census: 9 AddRecord call sites, 2
  EmitFragment call sites, no tail jumps).
