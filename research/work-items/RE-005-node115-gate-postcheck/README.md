# RE-005 node 115: what the gates' later phases do with the embedded record

Packet type: static evidence (target-bound). Continues
RE-005-node115-key-consumers (PR #2604), whose open edge 4 asked
what the gate bodies gate_c (0x2cb6500..0x2cbbbdf, 22,239 B) and
gate_a (0x2aeaef0..0x2af0654, 22,372 B) do with the embedded
record after the key/config checks pinned there.

## Question

The key-consumers packet pinned the gates' early phase: each
gate manufactures a ("hl-node", 7) pair at embedded
+0x78/+0x80, runs a config-slot check and a log-only key
lookup, tests the tag byte, and dispatches on the +0x11c
outcome byte. Two observations were left open: the merged pair
is loaded once more late in each gate (gate_c
0x2cbb0ba/0x2cbb0c3; gate_a 0x2aefb11/0x2aefb29), and embedded
+0x90 is address-taken (gate_c 0x2cb6b4e/0x2cb715f) as a
sub-object base. (1) What processing do those belong to —
which fields of the embedded record do the post-check phases
read and write, which callees receive the record or its
sub-objects, and what is produced? (2) What determines the
returned outcome byte in the later phases — which conditions
set it, on which arms?

## Answer

**The gates are multi-entry state machines, and one call
advances the machine by one step.** The prologue dispatches on
byte [rbx+0x71] through a relative jump table (gate_c
0x60bb44, gate_a 0x6041ec; exactly five arms each). Three more
dispatches live inside: byte [rbx+0xd0] (table 0x60bb58, 9
arms), byte [rbx+0xad0] (table 0x60bb7c, 32 arms in gate_c
against 28 at 0x604224 in gate_a — a real clone divergence),
and byte [rbx+0x120] (table 0x60bbfc, 5 arms). Byte +0x120 is
the outcome channel and +0x71 the next-state channel: every
exit writes both before returning, and the shaper re-invokes
the gate until an exit returns 0.

**The late pair loads are an unwind-path free, not a second
consumption.** Gate_c loads [rbx+0x78] at 0x2cbb0ba and
[rbx+0x80] at 0x2cbb0c3 inside a landing-pad block, guarded by
flag byte [rbx+0x74] ≠ 0 and length > 0, and calls the dealloc
slot 0x64df4a0 with (pointer, length); it then clears the flag
(0x2cbb0d2) and joins the shared tail cleanup at 0x2cbbba8.
The flag is set on the normal path at 0x2cb6bc7
(`movw $0x100, 0x73(%rbx)`) immediately before the pair is
(re)built. A full rbx census of both gates shows these are the
only loads of +0x78/+0x80 besides the lookup arguments at
0x2cb68f6/0x2cb68fa (gate_a mirrors the free at
0x2aefb11/0x2aefb29 with a sentinel-and-zero test in place of
the signed test).

**The +0x90 address-takes set up the +0xd0 sub-machine.** At
entry state 4 (0x2cb6b40) the gate takes r15 = &[rbx+0xd0],
loads the state byte [rbx+0xd0], takes r13 = &[rbx+0x90]
(0x2cb6b4e) and dispatches through the +0xd0 table; the same
pair of address-takes recurs at state 0 (0x2cb715f). Inside
the arms, the +0x90 sub-object is processed through r13: a
direct call 0x26e11f0 at 0x2cb6ac0 (rsi = r15, rdx = r13,
r8 = 1), an insert through slot 0x64e0ec0 into &[rbx+0xc0] at
0x2cb6adf, and an element free loop (0x2cb6b20–0x2cb6b3e,
stride 0x18, dealloc via slot 0x64df4a0). The +0xd0 state-3
arm (0x2cb6b65) instead spills &[rbx+0xad0] to [rsp+0x50] and
&[rbx+0xd8] to [rsp+0x78] and dispatches the 32-state +0xad0
machine.

**The post-lookup +0x11c dispatch reshapes the record.** Tag
≠ 0 with [rbx+0x11c] == 2, and every [rbx+0x11c] != 1 arm,
land at 0x2cb6ba0: outcome 1 is written to record byte +0x120
through the &[rbx+0x120] pointer both merge paths spill to
[rsp+0x18] (0x2cb67b8, 0x2cb67e4); the +0xad0 sub-object is
destroyed (direct call 0x2c901a0 at 0x2cb6bad); the +0x74
ownership flag word is set (0x2cb6bc7); and the +0x78 pair is
rebuilt from the +0x48 triple (`movdqu [rbx+0x48] → [rbx+0x78]`
at 0x2cb6bd6, `[rbx+0x88] = [rbx+0x58]` at 0x2cb6bdf). The
== 1 arm instead allocates a 0x30-byte refcounted block (alloc
slot 0x64df480 at 0x2cb6939; refcount block {1,1,0,0,1,0}
stored at [rbx+0xa0]), calls builder 0x2d47710 on a stack
descriptor (0x2cb69b2), then writes the double bits
0x403e000000000000 (30.0) at [rbx+0xa8] and zeroes
[rbx+0xb0..+0xc0] (0x2cb6a3b).

**The returned byte is decided by an exit funnel over the
single ret** (gate_c 0x2cbb7e8; gate_a 0x2af024e). The
epilogue stores al through the [rsp+0x18] pointer (= record
+0x120), sets al = 1, and stores cl to [rbx+0x71]. Its
entries, derived by scanning every jump into the epilogue
span:

- **Outcome 3** — the +0x120 state-3 arm enters at 0x2cbb481,
  calls checker_b 0x2c7fa40 on &[rbx+0x128] with the saved
  context pointer as rsi (0x2cbb490); bit 0 of the result set
  → outcome 3 to +0x120, +0x71 := 3, return 1 (`jne 0x2cbb7c3`
  at 0x2cbb497). The zero arm continues through call 0x2ca3cd0
  on the same sub-object.
- **Outcome 4** — the +0x120 state-4 arm enters at 0x2cbb708,
  calls checker_a 0x2c7f360 on &[rbx+0x150] with the context
  pointer (0x2cbb717); nonzero → outcome 4 to +0x120,
  +0x71 := 3, return 1 (`jne 0x2cbb7c7` at 0x2cbb71e). The
  zero arm runs the [rbx+0x1e0] == 3 && [rbx+0x1d8] == 3
  checks, drops the +0x168/+0x170 refcounts, destroys the
  +0x178 group (0x2ca0790 at 0x2cbb76d), frees the
  +0x138/+0x140 pair (flag +0x11e) and the +0xd8/+0xe0 pair,
  and falls into the global-state phase at 0x2cbb0e6. A
  second flow reaches the same checker call after moving
  [rbx+0x130] → [rbx+0x150] and zeroing [rbx+0x1e0] (block at
  0x2cbb6f1); the table entry skips that prefix.
- **Wide-phase exit** — a phase touching record fields up to
  +0x2a1f, with stack copies of 0x138 and 0x7f0 bytes, exits
  when r12 == 2: byte 4 is stored through the [rsp+0x50]
  spill (0x2cb8029), byte 3 through the [rsp+0x20] spill
  (0x2cb802d), +0x71 := 4, return 1 (`jmp 0x2cbb7d4` at
  0x2cb8034). The r14 checker phase's nonzero arm enters this
  tail mid-way (`jmp 0x2cb802d` at 0x2cb9937 — the only jump
  to that address) after calling checker_a 0x2c7f360 on r14
  (0x2cb9923) and writing byte 3 through its r15 (0x2cb992c).
- **Return 0** — the same r14 phase's zero arm: after
  [rbx+0x168] == 3 && [rbx+0x160] == 3, the +0xf8 refcount
  group is dropped, 0x2ca0790 destroys &[rbx+0x100]
  (0x2cb9985), byte 1 is written through r15 (0x2cb998a),
  0x2ca3ab0 is called on r14, [rbx+0xd0] := 1 (0x2cb9996),
  the flag word at +0x73 is zeroed, +0x71 := 1, and the gate
  returns 0 (`jmp 0x2cbb7d4` at 0x2cb99a7) — the only zero
  return; the shaper then drops the record.
- **Unwind** — never reaches the ret: the pads write outcome
  2 and +0x71 := 2 ([rbx+0xad0] := 2 at 0x2cbb069, the
  +0x118/+0x120 pair freed under flag +0xad9, byte 2 stored
  through the [rsp+0x20] spill at 0x2cbb07f, 0x2ca14a0 called
  with rdi = [rsp+0x18] at 0x2cbb087), and the shared tail at
  0x2cbbba8 frees the +0x48 pair under its +0x73 flag, writes
  byte 2 to +0x120 (0x2cbbb9b), sets +0x71 := 2 (0x2cbbbc7)
  and resumes via _Unwind_Resume (0x2cbbbce).

**The global-state phase at 0x2cbb0e6** (exactly three
entries: 0x2cb707a, 0x2cbb7a9, 0x2cbb7be) is the same lazy-init
machinery as the early phase: it loads the global through
slot 0x64e0918, tests [global+0x50], and on the unset arm
completes initialisation through slot 0x64df9f0 with the
.data.rel.ro descriptor statics at 0x644da18/0x644da30 as
arguments (their file qwords are relocated pointers, not
text). The post-check phases also contain date/time
conversion blocks whose failure paths reference the .rodata
messages at 0x465ab7 ("Local time out of range for
`NaiveDateTime`", 43 B) and 0x4676bb ("a Display
implementation returned an error unexpectedly", 55 B).

**Gate_a mirrors the funnel with the same values.** Its
epilogue (0x2af0229) is entered from 0x2aefefd (checker clone
0x2a91280, bit-0 test, outcome 3), 0x2af0184 (checker clone
0x2a90a50, zero test, outcome 4), 0x2aeca14 (wide-phase twin,
+0x71 := 4) and 0x2aee477 (return-0 twin: [rbx+0xd0] := 1 at
0x2aee466, flag word zeroed at 0x2aee46d, +0x71 := 1). It has
no mid-tail entry. The clones swap two spill slots: gate_a's
&[rbx+0x120] spill lives at [rsp+0x20] and its context pointer
at [rsp+0x18] — the reverse of gate_c. Its drop_pair analogue
is 0x2abc7e0 (called on &[rbx+0x178] at 0x2af01d3) and its
drop_ad0 analogue is 0x2abd600 (0x2aefade).

## Precise negative

Which record bytes the [rsp+0x50] and [rsp+0x20] spills name
on the wide-phase exit (and on the unwind pad's byte-2 store
at 0x2cbb07f) is **not statically decidable** from the gate
body: both slots are redefined with unrelated values across
phases — [rsp+0x50] holds &[rbx+0x78] at 0x2cb67d6/0x2cb67f4
and stack-copy addresses in the wide phase; [rsp+0x20] holds
r15 saves at 0x2cb7014/0x2cb746f/0x2cb8400/0x2cb8c0e and an xmm
spill at 0x2cb6c02. The values written through them (4, 3 and
2 respectively), the guards, the +0x71 writes and the return
bytes are pinned; the two store targets are not.

## Method

`tools/gate_postcheck_static.py` re-derives everything from
the authenticated artifact on each run: both gates' full rbx
bracket censuses, all eight jump tables (bounds fixed by the
neighbouring table, targets checked to land inside the gate
bodies), the exit funnels (jump scans into each epilogue
span, single-ret check), the post-check direct-call sites,
byte pins at 61 gate_c and 21 gate_a sites, the GOT slots'
relocation facts, and the two strings — every string read
resolving through the section table (.rodata −0x0, .text
−0x1000, .data.rel.ro −0x2000 deltas per section). The two
gates are hash- and pin-pinned only; the six smaller
post-check callees (checker_a 955 B, checker_b 832 B,
drop_pair 136 B, drop_ad0 471 B, builder_11c 1,820 B,
phase90_call 1,136 B) are exported in full. Verify mode
regenerates records.json, frames.txt and the six exports
canonically, compares byte-for-byte and prints
`{"matches": true, "packet": "RE-005-node115-gate-postcheck"}`.

## Open edges

1. Equality callee 0x154c4e0's internals (carried from
   #2597/#2604): which descriptor fields it compares, and
   against which member of the crit-msg global.
2. The lookup callee's state constructor behind slot
   0x64e0b48 (body 0x1562670) — gate-side contract only here.
3. The "infra" callee behind slot 0x64e0eb0 (0x1534810):
   encountered only as an early-phase call in #2604; not
   chased in the post-check phases.
4. The checkers' own internals beyond their gate-side
   contracts (checker_a 0x2c7f360 / checker_b 0x2c7fa40 and
   their gate_a clones): which fields of the +0x128/+0x150
   sub-objects decide their verdict bytes.
5. Gate_a's extra five-entry table at 0x604214 and the
   remaining inner dispatch arms of the +0xd0/+0xad0
   machines beyond the arms traced here.
6. Who re-invokes the gate with +0x71 states 1 and 2: the
   entry arms at 0x2cb9f1d/0x2cb9f10 are lazy-init blocks;
   their caller-side trigger was not traced.
7. The two undecidable spill targets of the precise negative
   above — resolvable only with runtime evidence.

Not claimed: any runtime value of the record's fields, the
checkers' internal decision rules, the identity of the
[rsp+0x50]/[rsp+0x20] store targets on the wide-phase exit,
or any behaviour of 0x154c4e0 / 0x1562670 / 0x1534810 beyond
the boundaries above.
