# RE-001: twin inner queries 0x61b21f0 / 0x61b2760 (node #115)

Task ID: RE-001 (node #115 function map). Bounded question: what do
the twin routines at 0x61b21f0 (tag 5) and 0x61b2760 (tag 6) do end
to end — how does the throttle gate decide whether to build, how
does the handler chain pick a handler, what message do they build,
how is it framed and delivered — and who calls them?

## Bound to

- Target: node #115, `work/hl-node-115.bin`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (from `provenance/artifacts.json`)
- Twin tag 5 FDE: 0x61b21f0..0x61b2738 (1352 bytes)
- Twin tag 6 FDE: 0x61b2760..0x61b2ca8 (1352 bytes)
- Throttle gate FDE: 0x61b1930..0x61b19e7 (183 bytes)
- Limit check FDE: 0x61b1910..0x61b192b (27 bytes)
- Flag-bit setter FDE: 0x61b18b0..0x61b18c8 (24 bytes)
- Frame-and-deliver FDE: 0x61b1a10..0x61b1ac6 (182 bytes)
- ULEB128 encoder FDE: 0x61bd410..0x61bd4e9 (217 bytes)
- Frame builder FDE: 0x61b1260..0x61b13a3 (323 bytes)
- Caller FDEs: 0x5d553c0..0x5d554e4 (call site 0x5d55451),
  0x5d55520..0x5d55644 (call site 0x5d555b1)

## How to reproduce the excerpts

From the repository root:

```
objdump -d --start-address=0x61b21f0 --stop-address=0x61b2738 work/hl-node-115.bin
objdump -d --start-address=0x61b2760 --stop-address=0x61b2ca8 work/hl-node-115.bin
objdump -d --start-address=0x61b1930 --stop-address=0x61b19e7 work/hl-node-115.bin
objdump -d --start-address=0x61b1910 --stop-address=0x61b192b work/hl-node-115.bin
objdump -d --start-address=0x61b18b0 --stop-address=0x61b18c8 work/hl-node-115.bin
objdump -d --start-address=0x61b1a10 --stop-address=0x61b1ac6 work/hl-node-115.bin
objdump -d --start-address=0x61bd410 --stop-address=0x61bd4e9 work/hl-node-115.bin
objdump -d --start-address=0x61b1260 --stop-address=0x61b13a3 work/hl-node-115.bin
objdump -d --start-address=0x5d55429 --stop-address=0x5d55479 work/hl-node-115.bin
objdump -d --start-address=0x5d55589 --stop-address=0x5d555d9 work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
python3 research/work-items/RE-001-twin-inner-queries-21f0-2760-115/census.py
python3 research/work-items/RE-001-twin-inner-queries-21f0-2760-115/verify.py
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
  On the gate-true path the twins write a u32 0 at +0x00, a u16 0
  at +0x04 and a qword 0 at +0x08 (bytes 6..7 are padding, never
  written); on the build path the twins write nothing to the out
  record — it is filled by the delivery slot.
- `rsi` is the obj, kept in r12: chain head at `*(obj)`, limit at
  +0x08, throttle limit at +0x10, flag bits at +0x18, delivery
  target at +0x28, throttle counter at +0x30.
- `rdx` is a pointer to a u32 (saved at (%rsp), dereferenced once).
- `rcx` (r13) and `r8` (r14) are {data pointer at +0x00, length at
  +0x08} pairs. The seventh and eighth arguments arrive as a
  16-byte {data pointer, length} struct on the stack (the callers
  copy it with `movups`); the twins read the pointer from
  0xc0(%rsp) and the length into r15 from 0xc8(%rsp).
- Stack frame 0x88 bytes plus six callee-saved registers, canary
  at rsp+0x78. Value block at rsp+0x30: handler return value at
  +0x00, tag byte at +0x08, presence-mask qword at +0x10, message
  string at +0x18 (data +0x00, size +0x08, SSO buffer at rsp+0x58).
  The message string's own data/size fields double as the frame
  builder's message pointer/length (value block +0x18/+0x20).

### The twins are one routine compiled twice

The two whole-function excerpts are identical after normalizing
addresses: same instructions, same immediates, same branch
structure. The single semantic difference is the tag byte the
prologue stores on the stack — 0x5 for 0x61b21f0, 0x6 for
0x61b2760. That byte selects the gate's flag mask (0x04 vs 0x08)
and is carried through as the frame's second byte. Everything
else, including the caller shape, mirrors: the tag-5 twin is
called by the guarded query 0x5d553c0 (call site 0x5d55451) and
the tag-6 twin by its twin 0x5d55520 (call site 0x5d555b1); both
callers are pinned in open PR #2646.

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
  straight to the counter path. The twins' tags 5 and 6 select
  masks 0x04 and 0x08.
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
  address 0x5d4d490 (a `lea` immediate in the twin code). That
  address is the expected-slot walker pinned whole in the open
  PR #2985 packet; the RELATIVE relocation at 0x64ecf80 with
  addend 0x5d4d490 installs the same address in the global of
  that name at load time, but the twins compare against the
  immediate, not the global.
- While the slots match, the walk advances via +0x20, comparing
  each link's slot against the walker, for links 1..10. The
  first mismatching link's slot is called at once; when all
  eleven comparisons pass, the twelfth link's slot is called
  unconditionally. The slot is entered with `rdi` = the link and
  `rbp` = &message string; the twin does not set `rsi` at the
  call site, so the slot's second argument holds whatever the
  gate's virtual call left and is not pinned here (see
  unknowns). The slot's return value is stored in the value
  block at rsp+0x30. The walk never checks for a null link: at
  least twelve links must be reachable via +0x20 from `*(obj)`
  (recorded as an assumption, not an observation).

### Phase 3 — message build

- The presence-mask qword at rsp+0x40 accumulates bits through
  the flag-bit setter 0x61b18b0 (bitset.txt, whole function: sets
  bit `rsi` in `*(rdi)`, returns 1 exactly when the bit was
  clear): bit 4 and bit 5 always; bit 6 exactly when the pair-B
  length at *(r14 + 0x08) is nonzero; bit 7 exactly when the
  pair-C length in r15 is nonzero.
- Appends, in order, each guarded by `remaining =
  0x3fffffffffffffff - size` against the needed length, else
  `__throw_length_error` with `"basic_string::append"` (string
  at 0x4474d2, verified in the raw binary):
  the 8 raw mask bytes; LE32 of the u32 at *(rdx); ULEB128 of
  the pair-A length plus the pair-A bytes; when pair B is
  present, ULEB128 of its length plus its bytes; when pair C is
  present, ULEB128 of its length plus its bytes. Lengths are
  encoded with 0x61bd410 (varint.txt, whole function, shared
  helper also pinned whole in the open PR #2985 packet): 1 byte
  to 0x7f, 2 to 0x3fff, 3 to 0x1fffff, 4 to 0xfffffff, 5 above.
- Message layout: `mask8 || LE32(u32) || ULEB128(lenA) || A ||
  [ULEB128(lenB) || B] || [ULEB128(lenC) || C]`.

### Phase 4 — framing and delivery (0x61b1a10)

- Frame-and-deliver takes (out, obj, value block). It builds an
  empty SSO string and calls the frame builder 0x61b1260
  (framer.txt, whole function, shared helper also pinned whole
  in the open PR #2985 packet): the builder appends the 8 raw
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

## Consumers

- Twin tag 5: exactly 1 direct call + 0 tail jumps, at 0x5d55451
  in FDE 0x5d553c0..0x5d554e4.
- Twin tag 6: exactly 1 direct call + 0 tail jumps, at 0x5d555b1
  in FDE 0x5d55520..0x5d55644.
- Gate: exactly 5 direct calls + 0 tail jumps (0x61b1b28,
  0x61b1e7b, 0x61b2247, 0x61b27b7, 0x61b2dc8) — the twins plus
  three sibling routines in the 0x61b1xxx/0x61b2xxx query family.
- Limit check: exactly 1 direct call + 0 tail jumps, at
  0x61b1940 inside the gate.
- Flag-bit setter: exactly 15 direct calls + 0 tail jumps (8 in
  the twins, 7 in sibling routines).
- Frame-and-deliver: exactly 7 direct calls + 0 tail jumps (2 in
  the twins, 5 in sibling routines).
- Frame builder: exactly 5 direct calls + 0 tail jumps (1 in
  frame-and-deliver, 4 elsewhere including the notifier 0x61bca30
  from open PR #2985).
- ULEB128 encoder: 165 direct calls + 0 tail jumps (shared
  helper; only the six twin-family sites are listed in
  callers.tsv).
- 0 stored qwords and 0 RELATIVE relocations for every pinned
  routine — reached only by code, never by data.

## Relation to other work

- Open PR #2646 pins the twin guarded queries 0x5d553c0 /
  0x5d55520 that call these twins; this packet pins the
  callees and the complete gated query behavior behind them.
- Open PR #2985 pins the chain-dispatch notifier 0x61bca30, the
  expected-slot walker 0x5d4d490, the ULEB128 encoder and the
  frame builder. This packet reuses the walker only as a
  comparison constant and re-ships the encoder and builder
  excerpts verbatim so the packet verifies standalone; the
  notifier's message format (`ULEB128(len(tag)) || tag ||
  LE32(8) || LE32(1)`) differs from the twins' mask/u32/pairs
  format pinned here.

## Inferences (kept separate from observations)

- The two twins are one query routine compiled twice with
  different tag constants, the same shape as the guarded-query
  twins in open PR #2646 that call them.
- The gate is a throttle: the message is built only while the
  target's slot +0x20 return does not exceed the limit at
  obj+0x08, while the tag's flag bit is clear, and once every
  limit-at-obj+0x10 qualifying calls.
- The message's first 8 bytes are a presence mask, followed by
  a u32 and one to three ULEB128 length-prefixed byte strings.

## Unknowns

- The identities of the virtual slot +0x20 (limit check) and
  slot +0x10 (delivery) targets, and what the delivery slot
  writes into the out record.
- The second argument the chain-walk handler slot receives (see
  phase 2).
- The meaning of the flag bits at obj+0x18 and of the u32 the
  twins append after the mask.
- The owning functions behind the two caller FDEs beyond their
  call-site windows (pinned in open PR #2646).
- The sibling routines in the 0x61b1xxx/0x61b2xxx family that
  share the gate, the flag-bit setter, frame-and-deliver and
  the encoder.
