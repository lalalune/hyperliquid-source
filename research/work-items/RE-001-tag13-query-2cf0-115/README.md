# RE-001: tag-13 inner query 0x61b2cf0 (node #115)

Task ID: RE-001 (node #115 function map). Bounded question: what
does the tag-13 inner query at 0x61b2cf0 do end to end — how does
it handle a count mismatch between its two input ranges, how
does the throttle gate decide whether to build, how does the
handler chain pick a handler, what message does its record loop
build, how is it framed and delivered — and who calls it?

## Bound to

- Target: node #115, `work/hl-node-115.bin`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (from `provenance/artifacts.json`)
- Tag-13 query FDE: 0x61b2cf0..0x61b3596 (2214 bytes)
- Count-mismatch helper FDE: 0x61cf670..0x61cf767 (247 bytes)
- Mismatch cleanup fragment FDE: 0x61cf650..0x61cf666 (22 bytes)
- Shared cleanup fragment FDE: 0x61b2ca8..0x61b2ce2 (58 bytes)
- Throttle gate FDE: 0x61b1930..0x61b19e7 (183 bytes)
- Limit check FDE: 0x61b1910..0x61b192b (27 bytes)
- Flag-bit setter FDE: 0x61b18b0..0x61b18c8 (24 bytes)
- Frame-and-deliver FDE: 0x61b1a10..0x61b1ac6 (182 bytes)
- ULEB128 encoder FDE: 0x61bd410..0x61bd4e9 (217 bytes)
- Frame builder FDE: 0x61b1260..0x61b13a3 (323 bytes)
- Caller FDEs: 0x5d78b40..0x5d7a806 (tag-13 site 0x5d79107),
  0x61b45da..0x61b4609 (tag-13 site 0x61b456a),
  0x61b47a2..0x61b483b (tag-13 site 0x61b4739)

## How to reproduce the excerpts

From the repository root:

```
objdump -d --start-address=0x61b2cf0 --stop-address=0x61b3596 work/hl-node-115.bin
objdump -d --start-address=0x61cf670 --stop-address=0x61cf767 work/hl-node-115.bin
objdump -d --start-address=0x61cf650 --stop-address=0x61cf666 work/hl-node-115.bin
objdump -d --start-address=0x61b2ca8 --stop-address=0x61b2ce2 work/hl-node-115.bin
objdump -d --start-address=0x61b1930 --stop-address=0x61b19e7 work/hl-node-115.bin
objdump -d --start-address=0x61b1910 --stop-address=0x61b192b work/hl-node-115.bin
objdump -d --start-address=0x61b18b0 --stop-address=0x61b18c8 work/hl-node-115.bin
objdump -d --start-address=0x61b1a10 --stop-address=0x61b1ac6 work/hl-node-115.bin
objdump -d --start-address=0x61bd410 --stop-address=0x61bd4e9 work/hl-node-115.bin
objdump -d --start-address=0x61b1260 --stop-address=0x61b13a3 work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
python3 research/work-items/RE-001-tag13-query-2cf0-115/census.py
python3 research/work-items/RE-001-tag13-query-2cf0-115/verify.py
```

Or regenerate every excerpt at once with the packet's
`export_excerpts.py` (same commands, same windows). `verify.py`
re-runs the regeneration and checks every excerpt line byte-for-byte
against the raw binary, plus the census, the jump table, the
relocation record and the model. Note: mnemonics such as `endbr64`
in the excerpts are genuine instructions present in the target
binary, not placeholders; the excerpts are verbatim objdump output.

## Observations

### Inputs and frame

- `rdi` is the out record pointer, saved at rsp+0x18 and
  returned in rax. On the count-mismatch path the query writes
  a u32 2 at +0x00, a u16 0 at +0x04 and a heap buffer pointer
  at +0x08 (bytes 6..7 are never written); on the gate-true
  path it writes a u32 0 at +0x00, a u16 0 at +0x04 and a qword
  0 at +0x08; on the build path it writes nothing to the out
  record — it is filled by the delivery slot.
- `rsi` is the obj, saved at rsp+0x20: chain head at `*(obj)`,
  limit at +0x08, throttle limit at +0x10, flag bits at +0x18,
  delivery target at +0x28, throttle counter at +0x30.
- `rcx` (r12) points to a range of 16-byte records: begin at
  +0x00, end at +0x08, each record a {data pointer at +0x00,
  length at +0x08} pair.
- `rdx` (r13) points to a range of 8-byte elements: begin at
  +0x00, end at +0x08; each element's virtual slot +0x18 is
  called with no further arguments for the u32 appended to S2.
- Stack frame 0x118 bytes plus six callee-saved registers,
  canary at rsp+0x108. Value block at rsp+0xc0: handler return
  value at +0x00, tag byte at +0x08, presence-mask qword at
  +0x10, message string at +0x18 (data +0x00, size +0x08, SSO
  buffer at rsp+0xe8). The message string's own data/size fields
  double as the frame builder's message pointer/length (value
  block +0x18/+0x20). Two more stack strings: S2 at rsp+0x80
  (SSO buffer at rsp+0x90) and S3 at rsp+0xa0 (SSO buffer at
  rsp+0xb0). The record count sits at rsp+0x30, count*8 at
  rsp+0x28.

### Phase 0 — the count-mismatch prologue

- The query computes count A = (rcx.end - rcx.begin) / 16 and
  count B = (rdx.end - rdx.begin) / 8. When they agree, the
  main path runs. When they differ, the query builds two
  strings on the stack and calls the count-mismatch helper
  0x61cf670 (mismatch.txt, whole function) with (out, &str1,
  0, 2, &str2, 0), then checks the canary and returns the out
  pointer without touching the gate, the chain or the message.
- The first string is the 42 bytes at 0x966820: "the CFs size
  and keys size does not match!" (verified in the raw binary).
  The second string is empty (size 0); its stored pointer
  value 0x4376fd is never dereferenced on this path, only its
  zero size is read.
- The helper writes the code byte 2 at out+0x00, zero bytes at
  out+0x01..out+0x05, and a heap buffer pointer at out+0x08;
  it allocates first.size + 1 bytes (the second string is
  empty, so no ": " separator is written), copies the first
  string, NUL-terminates, stores the buffer at out+0x08, and
  frees the old buffer there with `_ZdaPv` when non-null (it
  is zero on this path). In general the helper joins two
  strings with ": " when the second is non-empty; it has 847
  direct callers and is a shared helper, not tag-13-specific.
- Its landing pad at 0x61cf75b jumps to the cleanup fragment
  0x61cf650..0x61cf666 (mismatch_cleanup.txt, whole fragment,
  its own FDE): frees *(rbx+0x08) with `_ZdaPv` when non-null,
  then `_Unwind_Resume`.

### Phase 1 — the throttle gate 0x61b1930

- The gate is called with (obj, &1-byte-tag) where the tag byte
  is 0x0d at rsp+0x5b. It first calls the limit check
  0x61b1910 (limit_check.txt, whole function): that loads the
  delivery target `*(obj + 0x28)` and calls its vtable slot
  +0x20 with no further arguments, then returns 1 exactly when
  the limit at obj+0x08 is below the slot's return value
  (unsigned). When the limit check returns nonzero, the gate
  returns 1: skip.
- Otherwise the gate reads the tag byte, subtracts 3, and
  dispatches through the jump table at 0x97c5f4 (jump_table.tsv;
  11 int32 entries, resolved byte-for-byte against the raw
  binary): tags 3, 4, 5, 6, 13 map to flag masks 0x02, 0x01,
  0x04, 0x08, 0x10; tags 7..12 and any tag outside 3..13 go
  straight to the counter path. Tag 13 selects mask 0x10.
- When a mask applies and (flag bits at obj+0x18 & mask) is
  nonzero, the gate returns 1: skip. When the masked bit is
  clear, the counter path runs: the counter at obj+0x30 is
  incremented; while the new counter is below the limit at
  obj+0x10 the gate returns 1 (skip); when it reaches the limit
  the counter is reset to 0 and the gate returns 0 (build).
- So the message is built only when all three hold: the
  target's slot +0x20 return does not exceed the limit at
  obj+0x08, the tag's flag bit is clear, and the throttle
  counter has reached its limit. The gate returns 1 for skip,
  0 for build; it has no canary.

### Phase 2 — handler selection (the chain walk)

- The head link's vtable slot +0x98 is compared against the
  address 0x5d4d490 (a `lea` immediate in the query code). That
  address is the expected-slot walker pinned whole in the open
  PR #2985 packet; the RELATIVE relocation at 0x64ecf80 with
  addend 0x5d4d490 installs the same address in the global of
  that name at load time, but the query compares against the
  immediate, not the global.
- While the slots match, the walk advances via +0x20, comparing
  each link's slot against the walker, for links 1..9. The
  first mismatching link's slot is called at once; when all
  nine comparisons pass, the tenth link's slot is called
  unconditionally — three links shallower than the tag-3/tag-4
  queries. The slot is entered with `rdi` = the link and the
  message-string address in r14; the query does not set `rsi`
  at the call site, so the slot's second argument holds
  whatever the gate's virtual call left and is not pinned here
  (see unknowns). The slot's return value is stored in the
  value block at rsp+0xc0. The walk never checks for a null
  link: at least ten links must be reachable via +0x20 from
  `*(obj)` (recorded as an assumption, not an observation).

### Phase 3 — message build

- The presence-mask qword at rsp+0xd0 gets bits 8, 9 and 10
  (0x700) through three flag-bit setter calls 0x61b18b0
  (bitset.txt, whole function: sets bit `rsi` in `*(rdi)`,
  returns 1 exactly when the bit was clear).
- The record loop runs once per record (index r15 stepping 8
  over count*8 bytes): the element is `*(elements.begin +
  r15)`, the record is `records.begin + r15*2`. Per element it
  calls virtual slot +0x18 on the element and appends the
  returned u32 as LE32 to S2; per record it encodes the length
  at record+0x08 with the ULEB128 encoder 0x61bd410 (varint.txt,
  whole function: 1 byte to 0x7f, 2 to 0x3fff, 3 to 0x1fffff, 4
  to 0xfffffff, 5 above) into a stack buffer and appends the
  encoded bytes plus the record's data bytes to S3. Each pair
  is appended unconditionally, even for a zero length.
- After the loop the message is assembled: the 8 raw mask
  bytes; LE32 of the record count; the ULEB128 of the S2 size
  (encoded from its low 32 bits) plus the S2 bytes; the ULEB128
  of the S3 size (encoded from its low 32 bits) plus the S3
  bytes. The S2 and S3 appends run even for a zero count (a
  single 0x00 varint byte each, no data).
- Message layout: `mask8 || LE32(count) || ULEB128(len(S2)) ||
  S2 || ULEB128(len(S3)) || S3`, where S2 is the concatenation
  of one LE32 per element and S3 the concatenation of one
  ULEB128(len) || data per record.
- Every append is guarded by `remaining =
  0x3fffffffffffffff - size` against the needed length, else
  `__throw_length_error` with `"basic_string::append"` (string
  at 0x4474d2, verified in the raw binary); nine length-error
  arms in this query, each checking the canary before throwing.

### Phase 4 — framing and delivery (0x61b1a10)

- Frame-and-deliver takes (out, obj, value block). It builds an
  empty SSO string and calls the frame builder 0x61b1260
  (framer.txt, whole function, shared helper also pinned whole
  in the open PR #3001 packet): the builder appends the 8 raw
  bytes of the return value at value block +0x00, one byte equal
  to the value block's +0x08 byte (the tag, 0x0d), LE32 of the
  message size at value block +0x20, then tail-jumps to
  `_M_append` with the whole message (data at +0x18).
- Frame layout: `raw8(handler return) || byte(tag) ||
  LE32(len(message)) || message`.
- Delivery is a virtual call, slot +0x10 on `*(obj + 0x28)`,
  with (out, target, &{framed data, framed size} view on the
  stack). The framed string is freed with a sized delete when
  its data is not the SSO buffer; the canary at rsp+0x38 is
  checked and the out pointer is returned. The out record is
  filled by the delivery slot, not by this routine.

### Cleanup on exception

- The query has two landing pads at 0x61b3576 and 0x61b3582.
  Both move the exception object into r12 and jump into the
  shared cleanup fragment 0x61b2ca8..0x61b2ce2
  (cleanup_shared.txt, whole fragment, its own FDE): the twin
  tag-6 routine's cleanup, sitting between the twin tag-6 FDE
  (ends 0x61b2ca8) and the tag-13 FDE (starts 0x61b2cf0). The
  first pad enters at 0x61b2ca8 and disposes all three stack
  strings (S3 via rbx, S2 via 0x8(%rsp), message via rbp); the
  second pad sets rbp to the message string and enters at
  0x61b2cba, disposing only the message. The fragment then
  checks the canary at rsp+0x108 and calls `_Unwind_Resume`.
  The exact throw-site to landing-pad mapping is not decoded
  from the exception table (see unknowns); the register-to-string
  mapping above is what the append call sites hold.
- The normal path instead disposes the S2, S3 and message
  strings inline (sized delete of capacity+1 when each data
  pointer is not its SSO buffer) before the canary check and
  return.

## Consumers

- Tag-13 query: exactly 3 direct calls + 0 tail jumps, at
  0x5d79107 in FDE 0x5d78b40..0x5d7a806, at 0x61b456a in FDE
  0x61b45da..0x61b4609, and at 0x61b4739 in FDE
  0x61b47a2..0x61b483b. The first caller follows the tag-4
  caller pattern (a 0x606ca40 call first, obj from +0x650,
  null-checked); the other two callers first zip a qword array
  and a 16-byte-record array into the two ranges with copy
  loops, then free both ranges with sized deletes after the
  call.
- Count-mismatch helper: 847 direct calls + 0 tail jumps
  (shared helper; only the tag-13 query's site 0x61b2d7f is
  listed in callers.tsv).
- Gate: exactly 5 direct calls + 0 tail jumps (0x61b1b28,
  0x61b1e7b, 0x61b2247, 0x61b27b7, 0x61b2dc8) — the tag-3 and
  tag-4 queries, the twins, and this tag-13 query, the fifth
  gate caller.
- Limit check: exactly 1 direct call + 0 tail jumps, at
  0x61b1940 inside the gate.
- Flag-bit setter: exactly 15 direct calls + 0 tail jumps (1 in
  tag 3, 2 in tag 4, 8 in the twins, 3 in the tag-13 query, 1
  elsewhere).
- Frame-and-deliver: exactly 7 direct calls + 0 tail jumps (1
  in tag 3, 1 in tag 4, 2 in the twins, 1 in the tag-13 query,
  2 in sibling routines).
- Frame builder: exactly 5 direct calls + 0 tail jumps (1 in
  frame-and-deliver, 4 elsewhere including the notifier 0x61bca30
  from open PR #2985).
- ULEB128 encoder: 165 direct calls + 0 tail jumps (shared
  helper; only the eleven query-family sites are listed in
  callers.tsv).
- 0 stored qwords and 0 RELATIVE relocations for every pinned
  routine — reached only by code, never by data.

## Relation to other work

- Open PR #3001 pins the tag-5/tag-6 twin inner queries and the
  same shared helpers (gate, limit check, flag-bit setter,
  frame-and-deliver, ULEB128 encoder, frame builder, gate jump
  table). Open PR #3004 pins the tag-3/tag-4 inner queries and
  the same helpers. This packet pins the gate's fifth and
  largest query sibling and re-ships those helper excerpts
  verbatim so the packet verifies standalone; the tag-13 query
  completes the gate's caller family (tags 3, 4, 5, 6, 13).
- Open PR #2985 pins the chain-dispatch notifier 0x61bca30, the
  expected-slot walker 0x5d4d490, the ULEB128 encoder and the
  frame builder. This packet reuses the walker only as a
  comparison constant and re-ships the encoder and builder
  excerpts verbatim so the packet verifies standalone.
- The shared cleanup fragment 0x61b2ca8..0x61b2ce2 is the twin
  tag-6 routine's cleanup (pinned in the open PR #3001 packet
  only as the twin's FDE end); it is pinned whole here because
  the tag-13 query's landing pads enter it.

## Inferences (kept separate from observations)

- The tag-13 query is the fifth caller of the throttle gate and
  the largest of the query family: same gate, handler-chain
  walk, framing and delivery as the tag-3/tag-4 queries and the
  tag-5/tag-6 twins, but a count-mismatch prologue, a record
  loop and a nine-comparison walk (three links shallower than
  the tag-3/tag-4 queries).
- The gate is a throttle: the message is built only while the
  target's slot +0x20 return does not exceed the limit at
  obj+0x08, while the tag's flag bit is clear, and once every
  limit-at-obj+0x10 qualifying calls.
- The first tag-13 caller follows the tag-4 caller pattern
  (0x606ca40 first, obj from +0x650, null-checked); the other
  two callers first zip a qword array and a 16-byte-record array
  into the two ranges, then free both ranges after the call.
- The tag-13 message's first 8 bytes are a presence mask with
  only bits 8, 9 and 10 set (0x700), followed by LE32(count)
  and the two length-prefixed strings S2 and S3.
- The second landing pad (message only) covers the handler-walk
  region, where S2 and S3 are not yet built; the first landing
  pad (all three strings) covers the loop and append region.

## Unknowns

- The identities of the virtual slot +0x20 (limit check) and
  slot +0x10 (delivery) targets, and what the delivery slot
  writes into the out record.
- The second argument the chain-walk handler slot receives: the
  query does not set rsi at the call site, so it holds whatever
  the gate's virtual call left; only rdi = the link and the
  message-string address in r14 are pinned.
- The meaning of the flag bits at obj+0x18, of the mask bits 8,
  9 and 10, and of the u32 each element's slot +0x18 returns.
- The identity of the 16-byte records and the 8-byte elements,
  and what the "CFs" in the mismatch message stands for.
- The owning functions behind the three caller FDEs beyond
  their call-site windows.
- The exact throw-site to landing-pad mapping in the exception
  table for the two landing pads.
