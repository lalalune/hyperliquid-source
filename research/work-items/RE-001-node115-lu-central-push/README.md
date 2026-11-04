# RE-001-node115-lu-central-push

## Question

Packet #204's next question: decode the actual central push `0x63c0340` —
what is the seg+0x2998 push-list object, what are its two virtual methods
(obj+0x18 vs obj+0xf338, selected by block-header bit 0x4000), and what does
the `&flag` out-parameter mean (nonzero = fallback to `0x6360610`)?

## Answer (short)

- The seg+0x2998 object is a sub-structure embedded in the segment metadata,
  not a standalone allocation. Its fields observed here: +0x8 atomic page
  counter, +0x18 method-A subobject, +0x50 fallback-route field (seg+0x29e8,
  passed to `0x635fb50`), +0xf338 method-B subobject, +0x10aa8 segment field
  (seg+0x13340) passed to the two pre-push helpers.
- The push itself (`0x63c0340..0x63c03e8`, 168B / 45 strict instrs) first
  runs the pre-push helpers, stamps the block header (bits 20–27 := 0xe8),
  page-masks block+0x8, and atomically subtracts the block's page count
  (block+0x10 >> 12) from obj+0x8. It then tail-jumps through a runtime
  function pointer: header bit 0x4000 clear selects subobject obj+0x18 and
  method [obj+0x38]; bit set selects obj+0xf338 and method [obj+0xf358].
  The method is invoked as method(thread, subobject, block, &flag).
- The two method pointees are runtime-stored function pointers. No static
  writer of [seg+0x29d0] / [seg+0x11cf0] exists in the file, and no
  `.rela.dyn` entry covers them (they live in per-segment memory, not in
  file-backed relocations), so their identities are NOT recoverable from
  the file alone. This is stated, not inferred around.
- `&flag` is the method's out-parameter: 0 = push complete, nonzero = the
  caller must run the fallback `0x6360610(thread, seg)`. The fallback is
  itself gated (seg+0x10f40, `.bss` byte `0x6711ab8`, per-index table byte)
  and either routes to `0x635fb50` (with seg+0x29e8), tail-jumps to
  `0x635f4b0`, or returns doing nothing.
- Census: 9 direct E8 callers in 7 FDEs, 0 E9, 0 LEA, 0 GOT. The central
  push is shared well beyond the flush path: page sink `0x63bd6c0`,
  page-owning free `0x63637f0`, and three further FDEs call it with the
  same (thread, seg+0x2998, block, &flag) convention and flag check.

## Scope

- Included: FDE `0x63c0340` end-to-end; the two push-wrapper flag tails
  (`flag_large`, `flag_small`); the fallback gate (`fallback_gate`); the
  whole-`.text` census; the cold-path helper `0x63aed40` and the
  always-run helper `0x63aefe0` characterised at call/role level only.
- Excluded (not decoded here): the two runtime method pointees' bodies;
  full decodes of `0x63aed40` / `0x63aefe0` / `0x635fb50` / `0x635f4b0`;
  the semantic label of header bit 0x4000 and bit 0x1000 beyond the exact
  tests observed; all `.bss` contents.

## Claims (address-cited vs excerpt-exhibited)

Excerpt-exhibited (bytes shipped): the full push FDE, both flag tails,
the fallback gate. Address-cited (exact key bytes checked by the verifier
and tests, but no excerpt shipped): the 9 census call sites, the fallback
inner calls (`0x6360684` seg+0x10ec8, `0x63606b7` seg+0x29e8), the
`0x635fb50` record-C pattern, and the `0x63aed40`/`0x63aefe0` roles.

## Key addresses

- Push FDE: `0x63c0340..0x63c03e8` (168B, 45 strict).
- Pre-push: cold-only `0x63aed40` (header bit 0x1000 path, call at
  `0x63c03dd`); always-run `0x63aefe0` (call at `0x63c0369`, class arg
  0xe8, fifth arg 0).
- Header stamp: bits 20–27 := 0xe8 (`0x63c0383` mask, `0x63c0389` or);
  block+0x8 page-masked (`0x63c0377`); page count = block+0x10 >> 12;
  `lock sub` at `0x63c0397` against obj+0x8.
- Dispatch: bit 0x4000 test `0x63c039c`; lea +0x18 `0x63c03a4`; lea
  +0xf338 `0x63c03a8`; cmove `0x63c03b5` (clear → +0x18, set → +0xf338);
  method load [selected+0x20] `0x63c03bc`; tail jump `0x63c03ca`.
- Fallback: `0x6360610..0x63606ca` (186B); gate load seg+0x10f40
  `0x6360620`; `.bss` byte `0x6711ab8`; routes `0x635fb50` (call site
  `0x63606be`, seg+0x29e8 arg) and `0x635f4b0` (tail jump `0x6360695`).

## Corrections to earlier packets

1. **#204 extended.** #204 said the push helpers "converge on
   `0x63c0340`". True, and the census here adds 7 further E8 sites in 5
   other FDEs (page sink `0x63bd6c0` site `0x63bd730`, page-owning free
   `0x63637f0` site `0x6363ab6`, FDE `0x6361320` sites `0x636156e` /
   `0x63615e2` / `0x63616a1`, FDE `0x6362190` site `0x63627a9`, FDE
   `0x6364880` site `0x6364e28`), all with the same argument convention
   and flag check. The central push is a shared primitive, not a
   flush-private helper.
2. **#204 refined.** #204's "vtable tail-jump (obj+0x18 vs obj+0xf338)"
   is a cmove selection (bit clear → +0x18, bit set → +0xf338) whose
   indirect target is [selected+0x20], i.e. [obj+0x38] vs [obj+0xf358],
   and the selected subobject — not obj — is passed as the method's
   second argument.
3. **#204 confirmed and extended.** The obj+0x8 atomic decrement is
   confirmed; its subtrahend is identified as block+0x10 >> 12, and it is
   preceded by the header 0xe8 stamp and the block+0x8 page mask.
4. **#204 confirmed and extended.** The nonzero-flag fallback is
   confirmed; the fallback's own gating (seg+0x10f40, `.bss` byte
   `0x6711ab8`, per-index table byte) and its two routes are newly
   characterised. #204's guard list, slot arithmetic, and listed call
   sites are otherwise confirmed. No other earlier packet is corrected.

## Verification

- Static verifier `tools/node115_lu_central_push.py`: exit 0
- Unit tests `tests/test_node115_lu_central_push.py`: 8/8 pass
- MANIFEST: 13/13 entries match
- `make doctor`: analysis_ready true
- `make verify`: exit 0
- `make catalogue-check`: exit 0
- `make test`: 77 files attempted, 1 failed — the single failure is
  the pre-existing test_node115_catalogue Errno 18
  cross-device-link error; this packet's file [36/77] passes 8/8

## Next question

Decode the fallback's inner route `0x635fb50`: what does it do with the
record C at seg+0x10ec8 and the obj+0x18 reference (seg+0x29b0), and when
does the fallback's gating actually fire? Behind it, still open: the two
runtime method pointees ([seg+0x29d0] / [seg+0x11cf0] writers), the drain
helper `0x51e8720`, the field-drop callees `0x5a50a10` / `0x5a4d200`,
and #200's delegates `0x51f3e20` / `0x57ec1b0` and unwind callee
`0x1680cab`.
