# RE-005 node 115 — remaining edges (flag writer, runtime-data boundary, gate re-invocation)

This packet answers the three open edges the
insert-return packet (#2651) carried over from the
predicate-chain packet (#2617, open edges 1, 2) and the
gate-checkers packet (#2613, open edge 4). Everything
below is static evidence from the authenticated
hl-node 115 artifact only (105,896,032 bytes, SHA-256
`a6e2897c…5301`).

Four bodies are exported in full (`flag_writer`,
`advance`, `accessor`, `tls_dtor`); every other body is
extent/digest pinned in `records.json` and `frames.txt`.
Reproduce with `tools/remaining_edges_static.py`
(`--generate` regenerates; plain run verifies against
`records.json`).

## Edge 1 — who writes the wheel flag byte [wheel+0x30]: SETTLED

The setter (0x5cea7c0) tests the flag at 0x5cea881
(`movzx eax, byte [rbx+0x30]`) to pick its direct-store
arm. Its writer is exactly one traced body:

**`flag_writer` 0x5ce08e0..0x5ce0998 (184 bytes,
exported).** Its argument `rsi` is the driver
sub-object base; the wheel is `[rsi+0x50]` (formed at
0x5ce0934, `lea rax,[rsi+0x50]`), so the flag is
`[rsi+0x80]`:

- 0x5ce0926 `movzx ecx, byte [rsi+0x80]` — reads the
  flag; if it is already nonzero the body returns
  without storing or advancing;
- 0x5ce093d `xchg byte [rsi+0x80], cl` (cl = 1) — the
  only write to the byte in the traced set (store
  census over the body's `rsi` stores, machine-checked);
- 0x5ce0950 calls the advance body (0x5ceaa20) with
  target `u64::MAX`, firing every pending entry;
- before the store it asserts `dword [rsi+0x90] !=
  1_000_000_000` via the shared assert callee (slot
  0x64df770) with Location static 0x64c6fa8 (tokio
  `runtime/time/mod.rs`, line 190, col 32) and the
  115-byte "timers are disabled" message at 0x94ca6b.

So the flag is the driver's **closed** bit: set once,
at teardown, together with a full drain of the wheel.

**Callers (whole-.text direct census + RELATIVE
census, both machine-checked):** exactly two, no
data-held references —

- 0x5ceb47e in `flag_caller_1` 0x5ceb330..0x5ceb52a
  (506 bytes): calls it under the wheel lock byte
  (`lock cmpxchg [r15+0x50]` at 0x5ceb468) after a
  refcounted registry-removal phase — a handle-release
  path;
- 0x5cfc20d in `flag_caller_2` 0x5cfbfd0..0x5cfc29e
  (718 bytes): a task state-machine step that calls it
  when the task state dword != 3, after draining its
  work queue.

**Horizon [wheel+0x28]** (also carried by #2651): its
only writer in the traced set is the advance body
itself — store at 0x5ceabc4 in the exported `advance`
body (0x5ceaa20..0x5cead37, 791 bytes), on the
no-more-due arm, with the value derived from the
next-deadline body 0x5cf6390. Advance never accesses
[wheel+0x30] at all.

**Completeness.** Three machine-checked censuses bound
the writer search: (a) the whole timer cluster
0x5ce0000..0x5cf8000 contains exactly three byte-sized
stores to `[reg+0x30]` from a non-stack base —
lock-acquire `cmpxchg` sites at 0x5cf4842 / 0x5cf48d7 /
0x5cf4a52 in body 0x5cf47f0, whose base is a
first-argument object with map fields at +0xc0/+0xc8
and a refcount at +0xf8 (`lock dec [r14+0xf8]`): not a
wheel (traced wheel fields end at +0x30; wheel bases
always derive from a handle+selector field or the
+0x50 sub-object base); (b) the direct callers of
every wheel body are enumerated (bucket 2, insert 1,
setter 2, poll 0 direct — data-held only via slot
0x64dfe40, advance 2); (c) the flag writer and advance
have no RELATIVE references. A writer that reaches the
byte only through a computed pointer or a bulk copy
over the whole wheel struct is outside these censuses
and is recorded as an open edge, not silently assumed
away.

## Edge 2 — the runtime data behind the gate: BOUNDED NEGATIVE

**Stored (sec, nsec) pair.** The fields
[handle+sel+0x88] / [handle+sel+0x90] are only ever
*loaded* in the traced set: the builder 0x5cf2150
(assert), the conversion 0x5cead40 (two asserts and
the difference against the deadline), its twin
0x5ceae80 (exported pins 0x5ceae9d / 0x5ceaecf), the
flag writer (cmp at 0x5ce091a), and the two handle
drop bodies 0x5ce7f40 / 0x5cea100 (cmp `[obj+0x90]`
vs 1e9 before freeing the 0x1860-byte levels array).
No body in the chain, its callers or its callees
stores to either field from a handle base. The pair is
the runtime clock epoch the handle was built with —
runtime data, written by runtime construction outside
the traced chain. Closed as a bounded negative on the
load/store census above.

**TLS accessor cell.** The accessor 0x5cf2b50..0x5cf2c34
(228 bytes, exported) reads the thread-local cell at
`fs:-0x1130` (anchor at 0x5cf2b5a): counter +0x0, tag
+0x8, handle pointer +0x10 (loaded at 0x5cf2be7, then
`lock xadd [rdx], rsi` at 0x5cf2bf6 raises the handle's
first word), init-state byte +0x48 (0x5cf2b61). The
PT_TLS template (filesz 0xb20, memsz 0x1180; the cell
anchor is block offset 0x50, inside the file-backed
template) initialises the cell to **{counter 0, tag 2,
handle 0, state byte 0}** — tag 2 is the
no-live-context state the accessor's reset arm handles
(machine-checked from the `.tdata` bytes). The only
other traced body that writes the cell is its
destructor `tls_dtor` 0x5cdf410..0x5cdf457 (71 bytes,
exported), registered through the guard slot 0x64e0510
→ 0x5ca0d20 with the destructor passed in `rsi`: it
stores state byte 2 at 0x5cdf411 and drops the old
handle. A live handle pointer is installed by runtime
context-entry code that no traced body calls. Closed
as a bounded negative.

## Edge 4 — gate re-invocation and [record+0x1d8]: SETTLED (state 3 is an output)

**Who re-invokes the gates.** Whole-.text census
(machine-checked): gate_c (0x2cb6500, 22,239 bytes,
pinned) is called only from `driver_c` 0x2cde430
(10,657 bytes, pinned) — at 0x2cde6f4 with record
mode byte 2 and at 0x2cdf58b with mode byte 1; gate_a
(0x2aeaef0, 22,372 bytes, pinned) only from
`driver_a` 0x2ae41e0 (11,142 bytes, pinned) — at
0x2ae4627 / 0x2ae548c, same shape. Neither gate nor
driver has any RELATIVE reference. In both drivers the
record is `&[task+0x220]`, a sub-struct of the driver
task object, refilled from the driver's own fields
immediately before each call (mode byte [record+0x28]
:= 2 / 1, [record+0x70] := byte [task+0x1e8],
[record+0x71] := 0). Both drivers are called by one
`dispatcher` 0x2ae1690 (4,386 bytes, pinned) —
driver_a at 0x2ae1a47, driver_c at 0x2ae1eeb (driver_a
also from body 0x2b404b0 at 0x2b40577) — and the
dispatcher's only direct caller is the stack-context
`thunk` 0x2cd8370 (63 bytes, pinned) at 0x2cd83a2,
which has no direct caller and no RELATIVE reference:
the chain's top is a boundary (see open edges).

**State 3 is never a resumed input on this path.** At
every fully traced call site the checker state byte is
zeroed immediately before the call:

- gate_c zeroes [record+0x1e0] at 0x2cbb701 before the
  checker_a funnel call at 0x2cbb717, zeroes the
  r14-phase instance byte [rbx+0x168] at 0x2cb9914
  before the call at 0x2cb9923, and zeroes checker_b's
  dispatch byte [record+0x1c8] at 0x2cbb476 before
  the call at 0x2cbb490;
- driver_c's own direct checker_a call (instance
  &[r13+0x238], f64 threshold 5.0) zeroes [r13+0x2c8]
  at 0x2cdfe3a before the call at 0x2cdfe4f;
- the other censused checker_a callers do the same
  (0x2cc0592, 0x2cc6c9e zero their instance bytes
  first).

State 3 is *written by the checkers during the call*
(checker_a 0x2c7f360 sets [arg+0x88] := 3 and
[arg+0x90] := 3 on the predicate-nonzero arm) and
*consumed by the callers after it*: gate_c tests
[record+0x1e0] == 3 at 0x2cbb724; caller 0x2b905a0
tests [rbx+0x180] == 3 at 0x2b90b12 right after its
call at 0x2b90b05. So on the traced paths the
"resume" arm of the checker dispatch is unreachable
as an entry state; state 3 flows out of a call, never
into one.

**[record+0x1d8] provenance.** This field is the
&[record+0x150] checker_a instance's sub-state byte
([arg+0x88]). It has **no store anywhere in gate_c**
(access census over the whole 22,239-byte body,
machine-checked), and before the first funnel call its
value is never read: checker_a's entry dispatch reads
only [arg+0x90] — the byte the gate just zeroed — and
[arg+0x88] is read only on the state-3 re-dispatch,
which the zeroed entry byte makes unreachable on a
first call (and by the gate only after the call
returns). Its writers are checker_a itself (on every
fresh-arm outcome that can be observed later) and
driver_c's big-endian block copy at 0x2cdf724 — the
last of four bswap qword stores to record+0x1c0..0x1e0
in a later phase, after both gate calls. The
pre-first-call contents are construction leftovers in
the driver task object and are functionally dead.

## Not folded in: #2701's carried edges

The bucket-second-caller packet (#2701) carried two
edges — the owning object of the 0x64dfe40 method
table and the wheel list's poll-side consumer. They
are different objects from this packet's three edges
and are **not** folded in. One cross-check was run and
is negative: the advance body exported here does not
touch the wheel list head/tail fields [wheel+0x18] /
[wheel+0x20] (its list-shaped accesses are on entry
fields), so it is not that consumer either.

## Open edges

1. Two checker_a call windows (0x2b90b05 in body
   0x2b905a0, whose zero store to [rbx+0x180] sits at
   0x2b90ddb with untraced ordering, and 0x2cc7fb5 in
   body 0x2cc1120) and the gate_a-clone callers were
   not traced far enough to confirm the
   zero-before-call store; the checker resume arm's
   reachability through those callers stays open.
2. The stack-context thunk 0x2cd8370 has no direct
   caller and no RELATIVE reference in the artifact;
   the mechanism that invokes it (and thus how often
   the dispatcher re-invokes the drivers) is outside
   the two censused reference forms.
3. A writer of the wheel flag byte that works only
   through a computed pointer or a bulk copy over the
   whole wheel struct would be invisible to this
   packet's censuses.
4. #2701's two carried edges (0x64dfe40 table owner;
   wheel-list poll-side consumer) remain open and are
   untouched by this packet beyond the negative
   advance cross-check above.

## Overlap / duplicate disclosure

- Open-PR sweep on 2026-11-04 (89 open PRs, full list
  plus targeted RE-005 searches): no open PR answers
  any of these three edges. Jonas's #2656 is the
  RE-005 signable-serialisation body (0x36aa9a0), a
  different question. The dodoran8811 fail-closed
  series (#2662–#2686) touches other packets' tools,
  not this chain. The edges originate from our own
  merged packets #2617 / #2613 and our open #2651 /
  #2701, which carry them as open questions rather
  than answers.
- Bodies pinned here overlap earlier packets by
  citation only: setter / conversion / conv_twin /
  poll / builder were established by #2617, #2613,
  #2651 and #2701; this packet adds no second export
  of them.

## Files

- `flag_writer.objdump.txt`, `advance.objdump.txt`,
  `accessor.objdump.txt`, `tls_dtor.objdump.txt` —
  full Intel-syntax disassembly of the four exported
  bodies (path line normalised).
- `records.json` — artifact identity, extents/digests,
  slots, strings, the Location static, the TLS
  template census, all store/call/relative censuses,
  instruction pins, findings, open edges.
- `frames.txt` — the `readelf -wf` FDE lines for all
  exported and pinned bodies.
- `MANIFEST.sha256` — checksums of the above.
