# RE-001: map node #115 table-footer magic constants and the Build/DecodeFrom gate

Task: RE-001. Bounded question: which stored constants are the table
footer magics of node #115's embedded RocksDB, how does the footer
builder substitute them, what exactly does the footer decoder accept
at its entry gate, and which code references the constants?

Target: node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(bound via `provenance/artifacts.json`), upstream main `05bc2de30`
at the time of this work.

Routine identities are the vendor census labels already in this
repository (RE-002-node115-vendor-census, published-crate rebuild
comparison): 0x6168620 is `rocksdb::FooterBuilder::Build`, 0x6168780
is `rocksdb::Footer::DecodeFrom`, 0x61686e4 is its cold part, and
0x6167dd0 is `rocksdb::BlockHandle::EncodeTo`. The census establishes
byte similarity to a rebuild; it does not record the constants, the
substitution or the gate. Those are what this packet pins, from the
binary's own bytes alone.

## Answer in one paragraph

Four footer magic values live as two adjacent stored qword pairs in
`.rodata` (VA equals file offset in that LOAD segment):
0xdb4775248b80fb57 and 0x88e241b785f4cff7 at 0x97a0a0/0x97a0a8, and
0x4f3418eb7a8f13b8 and 0x8242229663bf9564 at 0x97bdf0/0x97bdf8.
FooterBuilder::Build (0x6168620) writes a 48-byte footer for format
version 0 — two BlockHandle encodings, zero padding to offset 40,
magic at offset 40 — and in that form substitutes the second value
of each pair for the first: a candidate 0x88e241b785f4cff7 is written
as 0xdb4775248b80fb57, and a candidate 0x8242229663bf9564 is written
as 0x4f3418eb7a8f13b8. For any other format version it writes a
53-byte footer (checksum-type byte at 0, handles from offset 1, zero
padding to 41, the 4-byte version at 41, the candidate magic
unchanged at 45). Footer::DecodeFrom (0x6168780) opens with a gate on
the buffer's trailing 8 bytes: the first-stored value of the block
pair is accepted (subject to the caller's expected value) and
normalized to the second; the first-stored value of the second pair
is likewise accepted and normalized; a trailing value equal to the
caller's expected value, or any trailing value when the caller
expects nothing specific, passes unchanged; anything else falls into
the corruption path that renders the found value into the
`Bad table magic number: expected ` message. A fifth magic,
0x926789d0c5f17873, exists only as an immediate passed by the cuckoo
builder; it is never stored.

## The constants

| Slot VA / file offset | Value | Role observed |
| --- | --- | --- |
| 0x97a0a0 | 0xdb4775248b80fb57 | block pair, written form ("legacy") |
| 0x97a0a8 | 0x88e241b785f4cff7 | block pair, current form |
| 0x97bdf0 | 0x4f3418eb7a8f13b8 | second pair, written form |
| 0x97bdf8 | 0x8242229663bf9564 | second pair, current form |

SHA-256 of the 16 bytes at 0x97a0a0:
`ae9a8a0c2b0866dd826d6d236ff958608192bd387ffc3716b0c032a848c40582`.
SHA-256 of the 16 bytes at 0x97bdf0:
`bb7d74c5824f2af157c372ad9e2208fd4f7b394363f6da335dbd7e0c063740f6`.

Stored-occurrence census (raw 8-byte search over the whole file):
the block written value occurs only at its slot; the block current
value occurs at its slot and once more as the immediate bytes of the
movabs at 0x60e80b2; the second pair mirrors this (written value only
at its slot; current value at its slot and in the movabs at
0x618df20). No relocation names any of the four slots.

## Build 0x6168620 (196 bytes)

Arguments follow the census signature: candidate magic (rsi),
format version (edx), a second size argument (rcx, not used by the
pinned paths), checksum type (r8b), and the two BlockHandles (r9 and
a stack argument). The routine builds the footer in a returned
std::string:

1. Format version 0: string length 48. The candidate is compared
   against the stored block current value (load at 0x6168643); on
   equality the stored block written value is loaded instead
   (0x61686d8). Otherwise it is compared against the stored second
   pair current value (0x616865b); on equality the stored second
   pair written value is loaded (0x61686c8). The resulting magic is
   stored at string offset 40 before the handles are encoded.
   Any other candidate is stored unchanged.
2. Format version nonzero: string length 53. The checksum-type byte
   is stored at offset 0, the format version as 4 bytes at offset
   41, and the candidate magic unchanged at offset 45. No
   substitution is performed on this path.
3. Both forms then call BlockHandle::EncodeTo (0x6167dd0) twice, the
   second call continuing where the first returned. The gap between
   the second encoding's end and the magic field (offset 40 or 41)
   is zero-filled with a tail call to memset; a zero gap skips it.

## DecodeFrom entry gate 0x6168780 (6,117 bytes; cold part 0x61686e4, 156 bytes)

The gate reads the trailing 8 bytes of the input buffer and the
caller-supplied expected value (r9; 0 means no specific expectation):

- Trailing == stored block written value (loaded at 0x61687a6):
  control reaches 0x6168f60, which loads the stored block current
  value; the value is accepted only if the expected value equals
  that current value or is 0 (otherwise the corruption path). The
  footer object stores the current value as its magic and type
  byte 5, and decoding continues with the 48-byte form at 0x6168f80.
- Trailing == stored second pair written value (compared at
  0x61687e3): control reaches 0x6168ec8, which loads the stored
  second pair current value; accepted only if the expected value
  equals it or is 0. The footer stores the current value, type
  byte 0, and decoding continues with the 48-byte form.
- Trailing == expected value, or expected == 0 (0x61687f6/0x6168802):
  the trailing value is stored unchanged (0x6168ee1). A trailing
  block current value branches to the continuation at 0x6169240;
  other values set type byte 0 and continue into the
  versioned-length path at 0x6168f08.
- No rule matches and expected != 0: the gate falls through at
  0x6168808 into the corruption construction; the found value is
  rendered into the message built around `Bad table magic number:
  expected ` (string at 0x95f500, loaded at 0x6168c50).

Only the gate is pinned. The handle decoding, version and checksum
checks after the gate, and the continuation at 0x6169240 are not
claimed here.

## Consumers

Census method: REX.W RIP-relative and movabs scans of the executable
LOAD segment with per-site objdump confirmation, an exhaustive
E8/E9 rel32 scan for direct transfers, smallest-enclosing-FDE
attribution, and a raw stored-occurrence scan; reproduced by
`census.py` and re-run inside `verify.py`.

Constant references: exactly 16 (14 RIP-relative, 2 movabs), listed
in `refs.tsv`. Inside the pinned routines Build references all four
slots; DecodeFrom references the block written slot, the second
pair written slot, the second pair current slot and the block
current slot; Footer::ToString (0x616a070..0x616bc9e) references the
block written and second pair written slots; BlockBasedTable::Open
(0x611fb10..0x61213db) references the block current slot;
PlainTableReader::PopulateIndex (0x61a0dc0..0x61a3c78) and
PlainTableReader::Open (0x61a4140..0x61a4d78) each reference the
second pair current slot. Identities are vendor census labels; the
bodies of these consumers are not pinned.

Direct calls to Build: exactly 3, 0 tail jumps — 0x60e8108 in
BlockBasedTableBuilder::WriteFooter (0x60e80a0..0x60e8218, candidate
block current value as the movabs at 0x60e80b2), 0x618df30 in
PlainTableBuilder::Finish (0x618dcb0..0x618eca7, candidate second
pair current value as the movabs at 0x618df20), and 0x61636a0 in
CuckooTableBuilder::Finish (0x6161440..0x616408a, candidate
0x926789d0c5f17873 as the movabs at 0x6163690, format-version
argument 1).

Direct calls to DecodeFrom: exactly 1, 0 tail jumps — 0x616da6a in
ReadFooterFromFile (0x616d2b0..0x616f6f2).

## Evidence packet

- `main.txt`, `cold.txt`, `decode.txt`: whole-function disassembly
  excerpts for Build, the DecodeFrom cold part and DecodeFrom,
  verbatim as objdump emitted them. The objdump header is normalized
  to the bare binary name only; every instruction line is
  byte-for-byte the binary's bytes (checked by `verify.py` against
  the raw file).
- `frames.txt`: the FDE lines for both pinned routines, the cold
  part, and every distinct caller function named by the census.
- `refs.tsv`: the 16 confirmed constant references.
- `callers.tsv`, `decode_callers.tsv`: the confirmed direct calls.
- `stored.tsv`: every raw occurrence of each constant value.
- `relocations.txt`: empty — no relocation references a constant
  slot or a pinned routine.
- `records.json`: semantic records only (no per-instruction detail).
- `export_excerpts.py`: regenerates the excerpts and frames from
  the binary. `census.py`: reproduces the censuses.
- `verify.py`: re-checks the digest, the manifest, the constant
  blocks against records.json, excerpt regeneration, excerpt bytes
  against the raw binary, the FDE ranges, all censuses with exact
  site lists, the empty relocation record, the semantic-only
  records, and model spot checks.
- Model `tools/footer_magic_115.py` with tests
  `tests/test_footer_magic_115.py`: the Build layout/substitution
  rules and the DecodeFrom entry gate. The BlockHandle varint
  encoding is modeled as an input to Build; only its two sequential
  EncodeTo calls and the zero padding are pinned by this packet.

Regeneration commands:

```
objdump -d --start-address=0x6168620 --stop-address=0x61686e4 work/hl-node-115.bin
objdump -d --start-address=0x61686e4 --stop-address=0x6168780 work/hl-node-115.bin
objdump -d --start-address=0x6168780 --stop-address=0x6169f65 work/hl-node-115.bin
readelf --debug-dump=frames-interp work/hl-node-115.bin
```

## Observations and unknowns

- The written/current pairing is observed, not named from source:
  in each pair the value stored first is the one Build writes into
  legacy-form footers and the one DecodeFrom's gate matches against
  the file, and the value stored second is the normalized/current
  form both routines converge on. This matches the block pair's
  public RocksDB names (legacy vs current block magic), but no
  reference source was used as a correctness oracle.
- The second pair's consumers are the plain-table builder and
  readers (vendor census labels), and its written value is accepted
  by the same gate, so it plays the identical role for a second
  table format. Its source-level name is not pinned.
- The cuckoo candidate 0x926789d0c5f17873 is passed only in the
  versioned form (format-version argument 1), so no written-form
  counterpart for it is observed anywhere in the binary.
- Not pinned: DecodeFrom past its entry gate (handle decoding,
  version/checksum validation, the 0x6169240 continuation), the
  bodies of the eight consumer functions, and any other file-format
  magics elsewhere in the binary (for example log or blob formats),
  which this census does not cover because it is keyed to the four
  stored constants and the two pinned routines.
