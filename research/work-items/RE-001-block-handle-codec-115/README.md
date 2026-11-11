# RE-001: pin node #115 BlockHandle wire codec at 0x6167d00/0x6167dd0/0x6167e30 with leaf 0x61bd540

Bounded question: what is the exact byte layout of a BlockHandle in
node #115's embedded RocksDB, what do its two encoders emit, what
does its decoder accept and reject, and what state does a failed
decode leave behind?

Target: node #115 work binary `work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(bound to provenance/artifacts.json for node #115).

Function names below are the RE-002 vendor-census labels for these
addresses. The census records identification and rebuild byte
similarity only; the byte rules, failure states and caller census
here are this packet's own, read from the target bodies and
checked by emulation (see Validation).

## What is pinned

A BlockHandle is two uint64 fields: `offset` at this +0x0 and
`size` at this +0x8. Its wire form is `varint64(offset)` followed
by `varint64(size)` — unsigned LEB128, 7 bits per byte, low groups
first, continuation bit 0x80 on every byte but the last of each
varint, at most 10 bytes per varint, 20 per handle.

Encoders:

- `EncodeTo(char*)` at 0x6167dd0 (93 bytes) emits the two varints
  with the loop `while value > 0x7f: emit (value | 0x80) low byte;
  value >>= 7`, then the final low byte, and returns the pointer
  one past the last byte written. It performs no bounds checking;
  the caller guarantees the space.
- `EncodeTo(std::string*)` at 0x6167d00 (200 bytes) assembles the
  same bytes in its stack frame and appends them through
  `std::string::_M_append`, guarded by a max-size check
  (`0x3fffffffffffffff` minus the current size) that throws
  `std::length_error` ("basic_string::append") instead of
  appending. It returns void (the exit register holds the stack
  canary difference, 0 on the success path).

Decoder: `DecodeFrom` at 0x6167e30 (247 bytes) parses the two
varints from the input Slice through the leaf at 0x61bd540
(GetVarint64Ptr, 75 bytes) with `limit = data + size`, storing the
first result into `offset` and the second into `size`. After each
successful varint it commits the slice advance (new data pointer
and remaining size) before parsing the next one.

Leaf rule (0x61bd540), which is therefore part of the codec's
acceptance rule: the limit is checked before every byte; a byte
with the continuation bit set ORs `(byte & 0x7f) << shift` into
the result, then `shift += 7`, and the decode fails if the shift
exceeds 63 — so a continuation bit on the 10th byte fails. A byte
with the bit clear ORs `byte << shift`, stores the result and
returns the next pointer. Consequences the bodies pin exactly:

- overlong encodings are accepted (a value padded with 0x80
  groups, up to the 10-byte cap);
- the 10th byte contributes only its lowest bit (shift 63 drops
  bits 1..6 of that byte), on the accepting path as well — a
  10-byte form of a value whose 10th byte is 0x7f decodes with
  only bit 63 set from that byte;
- running out of input at any point fails.

Failure state (DecodeFrom): the handle's two fields are zeroed
(a 16-byte zero store), and the body constructs a corruption
status through the constructor at 0x61cf670 with code 2, subcode
0, severity 0 and the message literal "bad block handle"
(0x437503, 16 bytes; second message empty). The slice is left
unchanged when the first varint fails, and advanced past the
first varint when the second fails (the first advance was already
committed). On success the body itself zeroes the status fields
(code/subcode/severity dwords and the state qword) before
returning it.

Twin: the std::string EncodeTo body exists a second time at
0x5f38b10 (200 bytes). The two bodies are byte-identical after
zeroing four position-dependent fields inside them (three E8
rel32 call displacements and one RIP-relative LEA displacement);
verify.py re-checks this. The twin is recorded, with its own two
call sites, but its component is not assigned here.

## Census (whole-file scan, reproduced by census.py)

- EncodeTo(std::string*) 0x6167d00: 6 direct calls, 0 tail jumps,
  0 stored qwords, 0 RELATIVE addends. Sites include
  MetaIndexBuilder::Add (0x61862e7, metaindex entries carry the
  handle as their value) and IndexValue::EncodeTo (0x61681f0);
  one site (0x6167f96) is inside the adjacent BlockHandle::
  ToString body, which is not pinned.
- EncodeTo(char*) 0x6167dd0: exactly 2 direct calls, both inside
  FooterBuilder::Build (0x616866b, 0x6168676) — the two handle
  slots of the table footer. No other caller exists. (The footer
  packet pins Build and the magic constants; the handle codec it
  calls is pinned here.)
- DecodeFrom 0x6167e30: 6 direct calls, 0 tail jumps, 0 stored
  qwords, 0 RELATIVE addends, including IndexValue::DecodeFrom
  (0x6168378) and FindOptionalMetaBlock (0x6184058).
- GetVarint64Ptr 0x61bd540: 49 direct calls (the two DecodeFrom
  sites among them), 0 tail jumps, 0 stored qwords, 0 RELATIVE
  addends. The other 47 sites are recorded as sites only.
- Internal transfers: EncodeTo(std::string*) calls _M_append,
  __throw_length_error and __stack_chk_fail (PLT); DecodeFrom
  calls the leaf twice, the status constructor once and
  __stack_chk_fail; the other three bodies make no calls. No
  indirect calls or tail jumps out of any of the five bodies.

## Validation

tools/block_handle_codec_115.py transcribes the four 0x6167
bodies plus the leaf. tests/test_block_handle_codec_115.py runs
15,086 pure-model checks (encoder vectors, decoder acceptance
including overlong and 10th-byte forms, failure states, 3,000
randomised round trips). Separately, the lane emulated all four
bodies under Unicorn against the model on 3,558 cases (1,212
leaf, 436 EncodeTo(char*), 1,610 DecodeFrom, 300
EncodeTo(std::string*)), 0 mismatches; the DecodeFrom runs hook
the status constructor to capture its arguments and the string
runs hook the _M_append PLT stub to capture the appended bytes.

## Evidence format

- encode_str.txt / encode_buf.txt / decode.txt / varint64.txt /
  twin_encode_str.txt: verbatim objdump excerpts of the five
  bodies (FDE ranges in frames.txt), regenerated by
  export_excerpts.py and re-checked byte-for-byte by verify.py
  against a fresh objdump run and the raw binary.
- callers.tsv: every confirmed direct call site with its
  smallest enclosing FDE and a context note.
- relocations.txt: intentionally empty — the census finds no
  stored qwords and no RELATIVE addends for any target.
- records.json: the semantic record verify.py checks.

## Not claimed

- The body of any caller (sites and FDE ranges only).
- BlockHandle::ToString at 0x6167f50 (adjacent, unpinned).
- What any handle points at in a specific block, index or
  footer; the footer gate and magic constants (covered by the
  footer packet, not here).
- GetVarint64Ptr behaviour at its other call sites beyond the
  shared byte rule pinned here.
- Which component the twin EncodeTo(std::string*) copy at
  0x5f38b10 serves.
