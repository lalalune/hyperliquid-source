# RE-001: node #94 WAL physical-record decode 0x5161400

Task ID: RE-001 (#94 function map). Bounded question: what does
node #94 0x5161400 do when it reads one physical WAL record —
how does it refill its block buffer, which header form applies,
which gates can reject the record, what do its return codes
mean, and where does the returned fragment come from?

## Bound to

work/hl-node-94.bin SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
matching provenance/artifacts.json for node #94.

## A note on the excerpts

The packet's disassembly files are verbatim objdump output for
whole functions, exactly as objdump emitted them. Instruction
detail that appears there (for example the `endbr64` at each
window start) is genuine content of the target binary, not
placeholders and not sanitized tokens. The JSON file in this
packet carries semantic records only; instruction-level detail
lives in the raw excerpt text files.

## What the window does

The window (0x5161400..0x516184d, FDE 0x0029b37c, 1101 bytes,
no padding — next FDE 0x5161850 starts immediately) decodes one
physical WAL record from the reader struct in rdi. It takes a
fragment out-pointer in rsi, a remaining out-pointer in rdx, and
a nullable transform out-pointer in rcx, and returns the record
type byte, or one of the special codes 10..15.

Reader fields used here: block-source handle +0x18, checksum
flag +0x28, second read argument +0x30, buffer pointer +0x38,
remaining +0x40, short-final-block flag +0x48, read-error flag
+0x49, final-block length +0x50, cumulative buffered count
+0x60, expected log number +0x68, sticky flag +0x70, stream
object +0x78, stream data pointer +0x80, scratch string +0x88
(pointer) / +0x90 (length), helper object +0xb0.

- Loop head and refill. When 6 or fewer bytes remain, the window
  calls the refill helper 0x51612a0 (352 bytes, FDE 0x00635270)
  and loops on a retry-true result, or returns the helper's code
  (10 or 12) on retry-false. A recyclable type with 10 or fewer
  bytes remaining refills the same way, because it needs the
  11-byte header.
- Refill helper. If the short-final-block flag (+0x48) or the
  read-error flag (+0x49) is already set, it reports the end:
  remaining 0 gives code 10, remaining > 0 writes the leftover
  size to the out parameter, clears the buffer, and gives code
  12. Otherwise it asks the block source for up to 0x8000 bytes
  (call at 0x5161367, slice pair at +0x38/+0x40). A nonzero read
  status clears the buffer, latches +0x49, and returns
  retry-true with code 10, so the next call takes the leftover
  path. A block of 0x7fff bytes or fewer sets +0x48 and records
  its length at +0x50; a full 0x8000-byte block does not.
- Headers. Plain records use a 7-byte header: CRC u32 at +0,
  length u16 at +4, type s8 at +6, payload at +7. Types 5..8
  (signed) use an 11-byte recyclable header with a log-number
  u32 at +7 and payload at +11. Every other type uses the
  7-byte form.
- Gates, in order. Header plus payload past the remaining
  buffer gives code 14 (remaining size written to the out
  parameter, buffer cleared). A zero type with zero length gives
  code 11 and clears the buffer (a trailer). A recyclable record
  whose log number differs from +0x68 gives code 13, and the
  buffer is left untouched on this path. When +0x28 is nonzero,
  the CRC gate runs: the stored CRC is unmasked as
  rotl15(stored − 0xa282ead8) and compared against CRC-32C
  extended from seed 0 over the type byte through the end of the
  payload (header_size + length − 6 bytes from buffer + 6); a
  mismatch gives code 15 (remaining size written to the out
  parameter, buffer cleared).
- Success. The buffer pointer advances past header + payload
  and the remaining count drops by the same amount. With no
  stream object (+0x78 null), the fragment is the payload slice
  inside the buffer. Type 9 (set-compression) also returns the
  buffer payload directly even when a stream object is present.
- Stream/transform paths. The scratch string (+0x88/+0x90) is
  reset first. With a NULL 4th argument, the window loops stream
  read calls (vtable slot +0x10); with a non-NULL 4th argument
  it creates the helper object (+0xb0) on first use and loops
  transform steps instead. Both loops continue while the status
  is nonzero or the chunk is a full 0x8000-byte block, append
  each chunk to the scratch string, and return the scratch
  string as the fragment; a negative status gives code 11 with
  the buffer cleared. On the transform path the cleanup call's
  result is written to the 4th argument.
- Sticky flag. When a recyclable header is seen while the
  cumulative buffered count (+0x60) equals the bytes remaining,
  +0x70 is set to 1 and never cleared by this window or its
  helper. What +0x60/+0x70 mean above that transition is not
  pinned here.
- Callers. Exactly 2 direct callers, both inside the logical
  reader 0x51618e0..0x516231c: 0x51619c6 (type-3 branch) and
  0x5161ec9 (general path). Both pass the same argument shape
  and treat codes above 15 as an error; no tail jumps and no
  qword references were found (full executable-segment scans
  plus a whole-file qword scan).

## What is not claimed

The stream object, the helper object, and the block-source call
are contracts, not pinned implementations: their method slots,
argument shapes, loop conditions and observable outcomes are
pinned, but what runs behind them is taken as caller-supplied
callables in the model. The CRC routine is reached through a
PLT import; the model implements standard CRC-32C and the tests
pin it against the published check value rather than claiming a
byte-level match with the linked routine. The empty-buffer
pointer stored on clear paths is 0x1e629b, the address of a NUL
byte immediately before a cargo-registry path string; it is an
empty-slice sentinel, not a claim about that path string. The
shape of this decode matches the WAL physical-record framing
used by log-structured storage engines; whether this instance
is first-party node code or a linked storage routine is left to
the maintainer, as in earlier items that mapped standard-library
shaped routines.

## Verification

`verify.py` checks the binary digest, regenerates every excerpt
byte-for-byte, checks MANIFEST.sha256, confirms records.json
carries semantic records only, and spot-checks recorded sites.
The model tests in tests/test_wal_physical_record.py cover all
return codes, both header forms, the CRC gate on and off, the
refill rounds, the sticky flag, the transform/read assembly
loops, packet verification, excerpt regeneration, sampled
instructions checked byte-for-byte, and two corruption controls.
