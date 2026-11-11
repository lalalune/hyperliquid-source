# RE-001: tag-3 and tag-4 inner queries 0x61b1af0 / 0x61b1e40 (node #115)

Task ID: RE-001 (node #115 function map). Bounded question: what do
the tag-3 and tag-4 inner queries at 0x61b1af0 and 0x61b1e40 do end
to end — how does the throttle gate decide whether to build, how
does the handler chain pick a handler, what message does each
build, how is it framed and delivered — and who calls them?

## Bound to

- Target: node #115, `work/hl-node-115.bin`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (from `provenance/artifacts.json`)
- Tag-3 query FDE: 0x61b1af0..0x61b1e18 (840 bytes)
- Tag-4 query FDE: 0x61b1e40..0x61b21ca (650 bytes)
- Throttle gate FDE: 0x61b1930..0x61b19e7 (183 bytes)
- Limit check FDE: 0x61b1910..0x61b192b (27 bytes)
- Flag-bit setter FDE: 0x61b18b0..0x61b18c8 (24 bytes)
- Frame-and-deliver FDE: 0x61b1a10..0x61b1ac6 (182 bytes)
- ULEB128 encoder FDE: 0x61bd410..0x61bd4e9 (217 bytes)
- Frame builder FDE: 0x61b1260..0x61b13a3 (323 bytes)
- Tag-3 cleanup fragment: 0x61b1ac6..0x61b1aeb
- Tag-4 cleanup fragment: 0x61b1e18..0x61b1e3d
- Caller FDEs: 0x5e8ef90..0x5e904bd (tag-3 sites 0x5e8f565,
  0x5e8f5a4), 0x5e909d0..0x5e91cd2 (tag-3 sites 0x5e90e06,
  0x5e90e42), 0x5e91ed0..0x5e9406a (tag-3 sites 0x5e922ca,
  0x5e92ebe, 0x5e92efa), 0x5d60fa0..0x5d623e0 (tag-4 site
  0x5d61261), 0x5e704c0..0x5e7151e (tag-4 site 0x5e706b9),
  0x5e7ca80..0x5e7d919 (tag-4 site 0x5e7cd24)

## How to reproduce the excerpts

From the repository root:

```
objdump -d --start-address=0x61b1af0 --stop-address=0x61b1e18 work/hl-node-115.bin
objdump -d --start-address=0x61b1e40 --stop-address=0x61b21ca work/hl-node-115.bin
objdump -d --start-address=0x61b1930 --stop-address=0x61b19e7 work/hl-node-115.bin
objdump -d --start-address=0x61b1910 --stop-address=0x61b192b work/hl-node-115.bin
objdump -d --start-address=0x61b18b0 --stop-address=0x61b18c8 work/hl-node-115.bin
objdump -d --start-address=0x61b1a10 --stop-address=0x61b1ac6 work/hl-node-115.bin
objdump -d --start-address=0x61bd410 --stop-address=0x61bd4e9 work/hl-node-115.bin
objdump -d --start-address=0x61b1260 --stop-address=0x61b13a3 work/hl-node-115.bin
objdump -d --start-address=0x61b1ac6 --stop-address=0x61b1aeb work/hl-node-115.bin
objdump -d --start-address=0x61b1e18 --stop-address=0x61b1e3d work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
python3 research/work-items/RE-001-tag3-tag4-queries-1af0-1e40-115/census.py
python3 research/work-items/RE-001-tag3-tag4-queries-1af0-1e40-115/verify.py
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

- `rdi` is the out record pointer, kept in rbx and returned in rax.
  On the gate-true path the queries write a u32 0 at +0x00, a u16 0
  at +0x04 and a qword 0 at +0x08 (bytes 6..7 are padding, never
  written); on the build path the queries write nothing to the out
  record — it is filled by the delivery slot.
- `rsi` is the obj, kept in rbp: chain head at `*(obj)`, limit at
  +0x08, throttle limit at +0x10, flag bits at +0x18, delivery
  target at +0x28, throttle counter at +0x30.
- Tag 3: `rdx` (r13) is a pointer to a record whose fields at
  +0x40 (data pointer) and +0x48 (length) form the single pair
  the query appends; the record's identity is not pinned.
- Tag 4: `rdx` (r13) is an object whose virtual slot +0x18 is
  called with no further arguments for the u32 appended after
  the mask; `rcx` (r12) is a {data pointer at +0x00, length at
  +0x08} pair.
- Stack frame 0x78 bytes plus six callee-saved registers, canary
  at rsp+0x68. Value block at rsp+0x20: handler return value at
  +0x00, tag byte at +0x08, presence-mask qword at +0x10, message
  string at +0x18 (data +0x00, size +0x08, SSO buffer at rsp+0x48).
  The message string's own data/size fields double as the frame
  builder's message pointer/length (value block +0x18/+0x20).

### The queries are siblings of the twins, not twins

The tag-3 and tag-4 queries share the skeleton of the tag-5/tag-6
twins pinned in the open PR #3001 packet — same gate call, same
handler-chain walk shape, same framing and delivery, same value
block layout — but they are not one routine compiled twice: the
tags differ (0x3 vs 0x4), the walk runs one link deeper (twelve
comparisons, thirteenth link, vs eleven and twelfth in the twins),
the payloads differ (tag 3: one pair from +0x40/+0x48 of the
third argument; tag 4: a u32 from a virtual slot plus one pair
from the fourth argument), and the register allocation differs
(tag 3 keeps the message string in r12, tag 4 in r14; the tag
byte sits at rsp+0x17 in tag 3, rsp+0x13 in tag 4).

### Phase 1 — the throttle gate 0x61b1930

- The gate is called with (obj, &1-byte-tag). It first calls the
  limit check 0x61b1910 (limit_check.txt, whole function): that
  loads the delivery target `*(obj + 0x28)` and calls its vtable
  slot +0x20 with no further arguments, then returns 1 exactly
  when the limit at obj+0x08 is below the slot's return value
  (unsigned). When the limit check returns nonzero, the gate
  returns 1: skip.
- Otherwise the gate reads the tag byte, subtracts 3, and
  dispatches through the jump table at 0x97c5f4 (jump_table.tsv;
  11 int32 entries, resolved byte-for-byte against the raw
  binary): tags 3, 4, 5, 6, 13 map to flag masks 0x02, 0x01,
  0x04, 0x08, 0x10; tags 7..12 and any tag outside 3..13 go
  straight to the counter path. Tag 3 selects mask 0x02, tag 4
  selects mask 0x01.
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
  that name at load time, but the queries compare against the
  immediate, not the global.
- While the slots match, the walk advances via +0x20, comparing
  each link's slot against the walker, for links 1..11. The
  first mismatching link's slot is called at once; when all
  twelve comparisons pass, the thirteenth link's slot is called
  unconditionally — one link deeper than the twins. The slot is
  entered with `rdi` = the link and the message-string address
  in the routine's string register (r12 for tag 3, r14 for tag
  4); the queries do not set `rsi` at the call site, so the
  slot's second argument holds whatever the gate's virtual call
  left and is not pinned here (see unknowns). The slot's return
  value is stored in the value block at rsp+0x20. The walk
  never checks for a null link: at least thirteen links must be
  reachable via +0x20 from `*(obj)` (recorded as an assumption,
  not an observation).

### Phase 3 — message build

- Tag 3: the presence-mask qword at rsp+0x30 gets bit 1 only
  (0x02) through the flag-bit setter 0x61b18b0 (bitset.txt,
  whole function: sets bit `rsi` in `*(rdi)`, returns 1 exactly
  when the bit was clear). Appends, each guarded by `remaining
  = 0x3fffffffffffffff - size` against the needed length, else
  `__throw_length_error` with `"basic_string::append"` (string
  at 0x4474d2, verified in the raw binary): the 8 raw mask
  bytes; the ULEB128 of the pair length (encoded from its low
  32 bits) plus the pair bytes. The pair is appended
  unconditionally, even for a zero length (a single 0x00 varint
  byte, no data).
- Message layout (tag 3): `mask8 || ULEB128(len) || data`.
- Tag 4: the mask qword gets bits 2 and 3 (0x0c) through two
  flag-bit setter calls. Appends, under the same guards: the 8
  raw mask bytes; LE32 of the u32 returned by virtual slot
  +0x18 on the third argument; the ULEB128 of the fourth
  argument's length (encoded from its low 32 bits) plus the
  pair bytes, appended unconditionally.
- Message layout (tag 4): `mask8 || LE32(slot18) ||
  ULEB128(len) || data`.
- Lengths are encoded with 0x61bd410 (varint.txt, whole
  function, shared helper also pinned whole in the open PR
  #3001 packet): 1 byte to 0x7f, 2 to 0x3fff, 3 to 0x1fffff, 4
  to 0xfffffff, 5 above.

### Phase 4 — framing and delivery (0x61b1a10)

- Frame-and-deliver takes (out, obj, value block). It builds an
  empty SSO string and calls the frame builder 0x61b1260
  (framer.txt, whole function, shared helper also pinned whole
  in the open PR #3001 packet): the builder appends the 8 raw
  bytes of the return value at value block +0x00, one byte equal
  to the value block's +0x08 byte (the tag), LE32 of the message
  size at value block +0x20, then tail-jumps to `_M_append`
  with the whole message (data at +0x18).
- Frame layout: `raw8(handler return) || byte(tag) ||
  LE32(len(message)) || message`.
- Delivery is a virtual call, slot +0x10 on `*(obj + 0x28)`,
  with (out, target, &{framed data, framed size} view on the
  stack). The framed string is freed with a sized delete when
  its data is not the SSO buffer; the canary at rsp+0x38 is
  checked and the out pointer is returned. The out record is
  filled by the delivery slot, not by this routine.

### Cleanup on exception

- Each query's landing pad (tag 3 at 0x61b1e0c, tag 4 at
  0x61b21be) moves the exception object into rbx and jumps into
  a cleanup fragment pinned whole here: tag 3's fragment at
  0x61b1ac6..0x61b1aeb disposes the message string (r12),
  checks the canary and calls `_Unwind_Resume`; tag 4's
  fragment at 0x61b1e18..0x61b1e3d does the same for its string
  (r14). The normal path instead disposes the message string
  inline (sized delete of capacity+1 when the data is not the
  SSO buffer) before the canary check and return.

## Consumers

- Tag-3 query: exactly 7 direct calls + 0 tail jumps, at
  0x5e8f565 and 0x5e8f5a4 in FDE 0x5e8ef90..0x5e904bd, at
  0x5e90e06 and 0x5e90e42 in FDE 0x5e909d0..0x5e91cd2, and at
  0x5e922ca, 0x5e92ebe and 0x5e92efa in FDE 0x5e91ed0..0x5e9406a.
  The first two caller FDEs walk a linked list (nodes via +0xf8)
  and issue one tag-3 query per node; the second call in each
  loop reloads the obj from +0x650 of a stack object.
- Tag-4 query: exactly 3 direct calls + 0 tail jumps, at
  0x5d61261 in FDE 0x5d60fa0..0x5d623e0, at 0x5e706b9 in FDE
  0x5e704c0..0x5e7151e, and at 0x5e7cd24 in FDE
  0x5e7ca80..0x5e7d919. All three callers call 0x606ca40 first
  and pass the obj from +0x650 of a register object,
  null-checked.
- Gate: exactly 5 direct calls + 0 tail jumps (0x61b1b28,
  0x61b1e7b, 0x61b2247, 0x61b27b7, 0x61b2dc8) — the tag-3 and
  tag-4 queries, the twins, and the tag-13 query.
- Limit check: exactly 1 direct call + 0 tail jumps, at
  0x61b1940 inside the gate.
- Flag-bit setter: exactly 15 direct calls + 0 tail jumps (1 in
  tag 3, 2 in tag 4, 8 in the twins, 3 in the tag-13 query, 1
  elsewhere).
- Frame-and-deliver: exactly 7 direct calls + 0 tail jumps (1
  in tag 3, 1 in tag 4, 2 in the twins, 3 in sibling routines).
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
  table). This packet pins the gate's other two small query
  siblings and re-ships those helper excerpts verbatim so the
  packet verifies standalone; the tag-13 query 0x61b2cf0, the
  fifth gate caller, is a separate work item (its count-mismatch
  prologue, two-string build and record loop need their own
  decomposition).
- Open PR #2985 pins the chain-dispatch notifier 0x61bca30, the
  expected-slot walker 0x5d4d490, the ULEB128 encoder and the
  frame builder. This packet reuses the walker only as a
  comparison constant and re-ships the encoder and builder
  excerpts verbatim so the packet verifies standalone.

## Inferences (kept separate from observations)

- The tag-3 and tag-4 queries are siblings of the tag-5/tag-6
  twins: same throttle gate, same handler-chain walk, same
  framing and delivery, but different tags, a one-link-deeper
  walk, and different payloads.
- The gate is a throttle: the message is built only while the
  target's slot +0x20 return does not exceed the limit at
  obj+0x08, while the tag's flag bit is clear, and once every
  limit-at-obj+0x10 qualifying calls.
- The tag-3 callers walk a linked list (nodes via +0xf8) and
  issue one tag-3 query per node, with the obj either carried
  in rsi or reloaded from +0x650 of a stack object; the tag-4
  callers each call 0x606ca40 first and pass the obj from +0x650
  of a register object, null-checked.
- The tag-3 message's first 8 bytes are a presence mask with
  only bit 1 set (0x02); the tag-4 message's mask has bits 2
  and 3 set (0x0c).

## Unknowns

- The identities of the virtual slot +0x20 (limit check) and
  slot +0x10 (delivery) targets, and what the delivery slot
  writes into the out record.
- The second argument the chain-walk handler slot receives (see
  phase 2).
- The meaning of the flag bits at obj+0x18 and of the u32 the
  tag-4 query appends after the mask.
- The identity of the record the tag-3 query reads at +0x40/+0x48
  of its third argument, and of the object the tag-4 query calls
  at slot +0x18.
- The owning functions behind the six caller FDEs beyond their
  call-site windows.
- The tag-13 query 0x61b2cf0..0x61b3596, the fifth gate caller,
  whose count-mismatch prologue, two-string build and record loop
  are a separate work item.
