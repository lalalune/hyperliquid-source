# RE-005 node 115: what the two gate checker bodies actually test

Packet type: static evidence (target-bound). Continues
RE-005-node115-gate-postcheck (PR #2606), whose open edge 5 asked
what the checker bodies at the end of each gate's funnel do:
checker_a (gate_c 0x2c7f360..0x2c7f71b, 955 B; gate_a clone
0x2a90a50..0x2a90e0b) and checker_b (gate_c
0x2c7fa40..0x2c7fd80, 832 B; gate_a clone
0x2a91280..0x2a915c0). Gate_c calls checker_b at 0x2cbb490 with
rdi = &[record+0x128] (bit 0 of the return drives funnel outcome
3) and checker_a at 0x2cbb717 with rdi = &[record+0x150] (a
nonzero return drives outcome 4); gate_c's r14 phase also calls
checker_a at 0x2cb9923 on a different pointer.

## Question

(1) Per checker: the argument sub-object's layout as the checker
sees it — every field offset read, every callee invoked (direct
and slot, with arguments), every store on normal and EH paths —
and the exact return-value rule. (2) Are the gate_a clones
byte-identical in logic or divergent? (3) Who writes the fields
the checkers read — gate, shaper, or earlier record life?
(4) What pointer does the r14-phase checker_a call pass, and is
it the same sub-object kind?

## Answer

**checker_a is a resumable validity machine over an f64.**
Its argument is a 0x98-byte sub-object: f64 value at +0x00,
copies at +0x08/+0x10, a 0x70-byte built struct S at
+0x18..0x88, sub-state byte at +0x88, state byte at +0x90.
Entry dispatches on [arg+0x90] (relative table 0x60af90):
states 1 and 2 are trap arms (the 25 B shims behind slots
0x64e1360/0x64e1368, with `base/src/lu.rs` location statics,
then ud2); state 0 is the fresh arm; state 3 re-dispatches on
[arg+0x88] (table 0x60afa0). Fresh arm: v := [arg+0x00],
[arg+0x08] := v. If v == ±0.0 the checker writes
[arg+0x90] := 1 and returns 0 without touching [arg+0x88].
If v < 0 it panics through slot 0x64df6b8 with the
`base/src/bucket_guard.rs` format pieces at 0x43b857 and
dl = 0; NaN reaches the same panic with dl = 1. If v > 0
finite, the checker decomposes v (biased exponent, 1e9-unit
scaling) into the inputs of the shared builder 0x5cf2150
(slot 0x64e13a0, descriptor static 0x644dc28), copies the
0x70-byte result into S, and runs the shared predicate
0x5cf2d30 (slot 0x64e0858) on S. Predicate nonzero →
[arg+0x88] := 3, [arg+0x90] := 3, return the predicate's eax.
Predicate zero → the handle pair is dropped (refcount dec on
[arg+0x20], drop fn chosen by byte [arg+0x18] between slots
0x64dfdc8/0x64dfdb8, drop_pair 0x2ca0790 on &[arg+0x28]),
states := 1, return 0. The resume arm with [arg+0x88] == 0
re-runs builder+predicate from v = [arg+0x10]; with
[arg+0x88] == 3 it calls the predicate directly on the
existing S. EH pads drop &[arg+0x28], &[arg+0x18] and
&[arg+0x10], write state 2 to both state bytes and
_Unwind_Resume.

**The predicate's decision is a converted-value test.** The
builder writes only S+0x00/+0x08 (the descriptor accessor
0x5cf2b50's pair), S+0x10 := 2, S+0x60 and S+0x68. The
predicate first consults a TLS cache (guard slot 0x64e0510):
TLS u16 low bit set and high byte 0 → call slot 0x64e0520 →
0x5cf3b90 and return 1. Otherwise, when [S+0x10] == 2, it
normalises S (refcount-inc on [S+0x08], conversion 0x5cf1d70,
[S+0x38] := −1, zeroes, then conversion 0x5cead40 with
[S+0x60] and dword [S+0x68]). It then traps when dword
[handle + (tag&1 ? 0x160 : 0x240) + 0x90] == 1,000,000,000
(assert-fail slot 0x64df770) or when byte [handle + base +
0x80] ≠ 0 (the bucket_guard "$min > max, or either was NaN"
panic), calls slot 0x64e0518 → 0x5ce91b0 on &[S+0x40]
(result unused), and returns 1 iff [S+0x38] != −1; 0 iff
[S+0x38] == −1 and byte [S+0x58] == 0; [S+0x38] == −1 with
[S+0x58] ≠ 0 unwinds through the "timer error: " piece at
0x433ed3. So checker_a returns nonzero exactly when the
predicate fast path fires or the normalised struct carries a
converted value at S+0x38 after the post-check call.

**checker_b is a one-poll-per-call handle machine.** Its
argument is a 0xa8-byte sub-object: source descriptor D at
+0x00 {cap, ptr, len, tag byte}, its working copy at
+0x20..0x40, a self-pointer slot at +0x40, built key struct B
at +0x48..0x68, the constant &str pair (0x451330, 16) —
"async_wait_inner" — written at +0x68 and again at +0x78,
the handle pointer at +0x88, and state bytes at
+0x90/+0x98/+0xa0. Entry dispatches on [arg+0xa0] (table
0x60afb0); states 1 and 2 trap. The fresh arm copies D to
+0x20, stores [arg+0x40] := &[arg+0x20] and [arg+0x98] := 0;
the resume arm re-dispatches on [arg+0x98] (table 0x60afc0)
and reloads D through [arg+0x40]. The string bytes are
copied to a fresh allocation (allocator slot 0x64df480,
memcpy slot 0x64df508; length 0 keeps sentinel buffer 1), B
is built, [arg+0x90] := 0, and the shared key builder
0x2b3c9d0 (direct call at 0x2c7fb66) stores a heap handle at
[arg+0x88]: a 0x100-byte object {state 0xcc at +0x00,
vtable 0x6449b00 at +0x10, B copied in}, built under the
spinlock on global word 0x64fee40 and inserted into a
registry through slot 0x64e7718 → 0x5cf5100 (a duplicate
insert panics with the "OS can't spawn worker thread: "
pieces at 0x431a60). The shared lookup 0x2e4adb0
(0x2c7fb84) then polls the handle: it presets the result tag
qword to 1 and calls vtable method [handle+0x10]+0x18 =
0x2b15630. The method writes nothing when its readiness
callee (slot 0x64dfe80 → 0x5cdb250, on &[obj+0x60]) returns
0, leaving tag 1; when ready it requires [obj+0x38] == 1 —
anything else panics with "JoinHandle polled after
completion" (0x6068d2) — sets [obj+0x38] := 2 and writes
result {tag 0, payload triple from obj+0x40..0x58}; the
lookup's TLS fast path also forces tag 1. **checker_b
returns bit 0 = the lookup result's tag byte**: tag ≠ 0 →
all three state bytes := 3 and return 1 (second return value
= the caller context); tag == 0 → CAS the handle state word
0xcc → 0x84 (contention calls the vtable drop 0x2b19230),
consume the payload triple through helper 0x2c7f720
(callback fn 0x24a7c50; its rax becomes the second return
value), state bytes := 1, free the source descriptor buffer
when [arg+0x20] != 0, return 0. EH pads drop B (0x2c93260)
and the [arg+0x40] descriptor (0x2ca6960), free the source
buffer, write state 2 everywhere and _Unwind_Resume.
Re-entry at [arg+0x98] == 3 dispatches on [arg+0x90]
(table 0x60afd0); its state-0 arm reloads the constant pair
from [arg+0x68]/[arg+0x70] and rejoins the keyhash phase
with the previously built B.

**The clones are logic-identical.** All five relative jump
tables reproduce the original arm offsets exactly, the
normalised instruction streams of both checker pairs (and of
the payload-helper pair) are equal, and the decision callees
are shared bodies: builder/predicate via the same slots,
keyhash/lookup by the same direct calls. The only per-family
differences are family-local drop glue — payload helper
0x2c7f720 vs 0x2a90e10 (both 227 B), drop_pair 0x2ca0790 vs
0x2abc7e0, and the EH drop bodies (gate_c 0x2c8b730 96 B /
0x2ca4700 114 B / 0x2c93260 62 B / 0x2ca6960 69 B; gate_a
0x2a9e950 96 B / 0x2ac0e00 114 B / 0x2aaab40 62 B /
0x2ac30e0 69 B) — plus each clone's own tables and location
statics.

**The gates write the tested fields; the shapers write none
of them.** A full rbx census of gate_c over record
+0x120..0x1f0 (in records.json) shows: checker_b's source
triple arrives on entry rounds through the verbatim 0x40-byte
copy at 0x2cb7225..0x2cb7255 that fills record+0x118..0x158
from a caller-supplied struct — gate-copied, not
gate-computed; in the funnel arm the gate overwrites +0x128
(0x2cbb552), +0x130 (0x2cbb610), +0x138..+0x148 (0x2cbb69e)
and +0x148 (0x2cbb68e) only after that arm's checker_b call.
checker_a's f64 at record+0x150 has exactly one gate store
(0x2cbb6f9), copying the gate-computed double at
[record+0x130] (a clamped computation from [record+0xa8]
through slot 0x64e7460 with constants 2.0 / −1.0 / 600.0 at
0x458eb0 / 0x458dc8 / 0x459568). Its state byte
[record+0x1e0] is zeroed by the gate at 0x2cbb701 immediately
before the call; [record+0x1d8] has no gate store at all —
only checker_a writes it. The #2604 bracket census records
no shaper access at the phase offsets of any of these
fields.

**The r14 phase runs checker_a on a second instance of the
same kind.** At 0x2cb98fc, r14 := &[rbx+0xd8]; the gate
stores the f64 constant 86400000000.0 (bits
0x42341dd760000000) at [rbx+0xd8] (0x2cb9903/0x2cb990d),
zeroes [rbx+0x170] and the instance state byte [rbx+0x168]
(0x2cb9914), and calls checker_a at 0x2cb9923 with
rdi = r14, rsi = the context spill. The zero path tests
[rbx+0x168] == 3 and [rbx+0x160] == 3 — the instance's
[arg+0x90]/[arg+0x88] — drops the handle pair at [rbx+0xf8]
under tag byte [rbx+0xf0] and calls drop_pair on
&[rbx+0x100] (its &[arg+0x28]) at 0x2cb9985, exactly
mirroring checker_a's internal layout. A nonzero return sets
[rbx+0x170] := 3 and joins the funnel mid-tail at 0x2cb802d
with outcome 4; a zero return sets [rbx+0x170] := 1, calls
cleanup 0x2ca3ab0 on &[rbx+0xd8] and reaches the return-0
arm. The two instances are staggered by 0x78 bytes, so
record+0x160/+0x168 are both the +0xd8 instance's state
bytes and the +0x150 instance's [arg+0x10] / S+0x00.

## Precise negative

Four points are not statically decidable from these bodies:
(1) which callee inside the predicate post-check chain
overwrites the −1 sentinel at S+0x38 — the conversion
0x5cead40 and the slot-0x64e0518 callee 0x5ce91b0 both run
between the sentinel store and the decision read, and their
internals are not pinned here; (2) the semantic identity of
method_b's readiness callee 0x5cdb250 beyond its
(obj, &[obj+0x60]) → al contract; (3) the producer of the
caller-supplied struct that gate_c copies into
record+0x118..0x158 at 0x2cb7225 — outside the gate body;
(4) the pre-first-call value of [record+0x1d8], which has no
writer inside the gates or the shapers.

## Method

Both checkers, both clones, and the decision callees
(builder_a, predicate_a, keyhash_b, lookup_b, method_b,
helper_b720 and its clone) are exported in full; the gates
and the two drop_pair bodies are hash- and frame-pinned
only. Every jump table and string is read through the
section table (.rodata identity, .text VA−0x1000,
.data.rel.ro VA−0x2000); GOT slots are resolved from
.rela.dyn addends; the gate census classifies every
rbx-relative objdump line in record+0x120..0x1f0; clone
equivalence is decided by normalised instruction streams
plus table-offset equality. `tools/gate_checkers_static.py`
re-derives all of it from the artifact and prints
`{"matches": true, "packet": "RE-005-node115-gate-checkers"}`
in verify mode; `tests/test_gate_checkers_static.py`
covers owners, tables, slots, pins, the census, canonical
regeneration, and byte/relocation mutation failures.

## Open edges

1. The predicate post-check chain: which of 0x5cead40 /
   0x5ce91b0 writes the converted value at S+0x38, and what
   value the builder's S+0x60/S+0x68 inputs become.
2. method_b's readiness callee 0x5cdb250 and the payload
   triple's semantics at obj+0x40..0x58 (consumed by helper
   0x2c7f720 through callback 0x24a7c50).
3. The producer of the struct copied into record+0x118..0x158
   at gate_c 0x2cb7225, i.e. where checker_b's source string
   ultimately comes from.
4. Who re-invokes the gates so checker states 3 (resume)
   are reached, and the pre-first-call provenance of
   [record+0x1d8].
