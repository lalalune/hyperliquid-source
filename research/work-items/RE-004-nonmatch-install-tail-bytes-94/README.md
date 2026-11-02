# RE-004: non-match install tail bytes (node #94)

## Claim status

- **Claim:** the five gate-pattern callers of #166/#167 install a 0x40-byte
  object on the non-match path — header (8 B) + trio-constructor output
  (0x30 B) + an 8-byte tail copied from stack slots the constructor never
  wrote. On the match path all five install only 0x38 bytes, leaving the
  object's 7th qword untouched.
- **Status: OBSERVED (byte-anchored).** Every install read, constructor
  output bound, decoder output field, destructor store, gate branch and
  trioC memcpy operand below is verified by
  `tools/nonmatch_install_tail_bytes.py` against node #94
  (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
  The writer census (no store to a tail slot on a path) is a full-FDE
  objdump store census; the generator anchors the instructions it rests on
  but does not itself disassemble (see Limitations).
- **Verdict split:** 4 of 5 non-match tails are never written on their
  path (trioA, double-gate, trioB, gate-like). TrioC's tail is
  **path-dependent**: unwritten on the null-decode path, written by a
  prologue memcpy on the hash path — from source bytes that were
  themselves never written (stale copy, not fresh data).
- **Answers #167's Next question (a):** who produces the 8 tail bytes?
  In 4 callers, nobody on the path does — the bytes are stale stack
  residue. In trioC, a prologue memcpy produces the slot's bytes on one
  path, but its source span is itself stale.

## Scope

### Included

- 5 gate-pattern callers (FDE extents from `.eh_frame`):
  trioA `0x4e6fd50..0x4e6fee2` (402 B), double-gate
  `0x4e852a0..0x4e85663` (963 B), trioB `0x4e856f0..0x4e85b12`
  (1058 B), gate-like `0x4e862b0..0x4e8673a` (1162 B), trioC
  `0x4e6bcb0..0x4e6c840` (2960 B).
- Each caller's non-match install (0x40 B), match install (0x38 B),
  landing-pad install (0x40 B), gate branch, decoder call, constructor
  call, header store and destructor call — see `installs.tsv`.
- The 2 decoder twins (`0x4e6f360`, `0x4e84500`, 812 B each), the 3
  trio constructors (501 B each, 6 output qwords), the 3 destructors
  (`0x4e6ed00` 181 B, `0x4e84440`/`0x4e6b870` 187 B each), helper
  `0x4e8c100` (390 B) and trioC's prologue memcpy.
- TrioC's two paths to its gate: null-decode (`je 0x4e6bf3a`) and
  hash path (prologue memcpy, then hash-map loop).

### Excluded

- The orchestrator `0x4e6fef0..0x4e713bd`: its join-block install is not
  a single 0x40-byte site (as in #167) and is not traced here.
- The wider non-tag-5 copy reads (callers reading decoder-buffer slots
  the decoder never wrote): observed, not claimed — they need their own
  per-caller writer census and are left as the Next question.
- Runtime contents of any tail slot: statically indeterminable (see
  Inferences). No execution of the node binary was performed.
- #157–#167 topics (decimals scaling, mul256 helpers/flags/difference
  writer, operand shapes, tag-5 twins, sentinel-gate family, non-rejoin
  paths, trio constructors) and #1543's fixed-eight topic: not rebuilt.

## The install shape

All five non-match installs copy the same 0x40-byte layout from a caller
stack buffer to the object:

| part | size | produced by |
| --- | --- | --- |
| header qword (= 1) | 8 B | explicit store before the install |
| constructor output | 0x30 B (6 qwords) | trio constructor A/B/C |
| tail qword | 8 B | **see verdict below** |

All five match installs write only 0x38 bytes (header + constructor
output) and never touch the object's 7th qword (`[obj+0x38..0x40]`).
So the 7th qword is written only on the non-match path, and there from
the tail slot. Per-caller ranges, calls and branches: `installs.tsv`.

Tail slots (stack offsets, all inside the caller's frame):

| caller | frame | install source | tail slot | verdict |
| --- | --- | --- | --- | --- |
| trioA | 0x70 | `[rsp+0x30..0x70]` | `[rsp+0x68..0x70]` (top qword) | unwritten |
| double-gate | 0xa8 | `[rsp+0x50..0x90]` | `[rsp+0x88..0x90]` | unwritten |
| trioB | 0xc0 | `[rsp+0x70..0xb0]` | `[rsp+0xa8..0xb0]` | unwritten |
| gate-like | 0xd0 | `[rsp+0x90..0xd0]` | `[rsp+0xc8..0xd0]` (top qword) | unwritten |
| trioC | 0x1f8 | `[rsp+0x30..0x70]` | `[rsp+0x68..0x70]` | path-dependent |

## Evidence

### Decoders write only 3 fields

Both 812-byte decoder twins (`0x4e6f360` for trioA, `0x4e84500` for
double-gate/trioB/gate-like) write exactly 3 fields of the caller's
buffer: byte `[out]=0x5`, qword `[out+0x8]`, byte `[out+0x10]`
(`4c896308` / `884310` / `c60305` at both instances). All other decoder
stores go to the decoder's own frame, heap arrays or the input struct;
no decoder call takes the caller's tail slot as an argument. The
decoders therefore cannot produce any tail byte.

### Constructors write exactly 6 qwords

Each 501-byte constructor writes `[out+0x0]` (tag slot), `[out+0x8]`
(`0x1e629b`), `[out+0x10]=1`, `[out+0x18]=0`, `[out+0x20]` (heap block),
`[out+0x28]=0` — and nothing past `[out+0x30]`. The tail sits at
`[out+0x30..0x38]` of the constructor's buffer (header is `[out-0x8]`
in install-source terms), one qword beyond the constructor's last
store. Verified for all 3 instances (tag-slot lea targets `0x574b9c0`,
`0x574ce30`, `0x574b950`).

### Destructors are object-only

All 3 destructors (`0x4e6ed00`, `0x4e84440`, `0x4e6b870`) contain only
`lock dec [rax]` stores (refcount decrements on heap objects) plus
object-pointer vtable calls. They receive the object pointer only, never
a caller stack address, so they cannot write a tail slot.

### Writer census (tail-writers.tsv)

For each caller, every callee that receives a pointer from which the
tail slot could be written was censused (16 rows total). In trioA,
double-gate, trioB and gate-like the complete set is decoder (3 fields),
constructor (6 qwords) and destructor (object-only) — none reaches the
tail. The only instructions in each caller FDE that touch its tail slot
are the two install reads themselves (normal install and landing-pad
install); see `segments.txt` for the exact instruction bytes at each
tail-covering read (10 rows: 5 callers x normal + landing pad).

### TrioC: two paths, two answers

TrioC inlines its decode instead of calling a decoder: helper
`0x4e8c100` (called at `0x4e6bd1e` with `rdi=[rsp+0x30]`) writes
`[out+0x0..0x30]` at most — 11 recorded stores, max offset `0x30`
exclusive (`movdqu [rax+0x20]` at `0x4e8c3de`). The tail at
`[out+0x38..0x40]` is 8 bytes above its reach.

- **Null-decode path:** after the helper returns, `test rbx,rbx; je
  0x4e6bf3a` (at `0x4e6bd2b`) jumps straight to the gate block
  (`0x4e6bf53`: header DWORD `[rbp]==4`, then sentinel compare vs
  `0x204be0`/`0x206160`, `cmp eax,0xffff`, `je 0x4e6c023` match,
  fall-through to the non-match constructor at `0x4e6bf8b`). No
  memcpy executes. On this path the tail is **unwritten**, like the
  other four callers.
- **Hash path:** the prologue runs a memcpy via PLT `0x576dfe0` at
  `0x4e6be1a` with `dst=[rsp+0x34]`, `src=[rsp+0x140]`, `len=0xb8`,
  writing `[rsp+0x34..0xec]` — which includes the tail slot
  `[rsp+0x68..0x70]` (source `[rsp+0x174..0x17c]`, offset `0x34` into
  the source). The loop is entered by fall-through from the memcpy,
  and every jump into the loop found in the FDE comes from the loop /
  hash-scan machinery itself or from gate-path blocks; the only
  entry-region bypass of the memcpy is the null-decode `je`. On this
  path the tail slot **is** written — but from a source span that no
  instruction before the memcpy writes: pre-memcpy stores to the source
  region are `[rsp+0x140]` (16 B), `[rsp+0x150]` (DWORD),
  `[rsp+0x1c8]`/`[rsp+0x1d8]` (16 B each), `[rsp+0x1e8]` (qword),
  `[rsp+0x1f0]` (byte), leaving a `0x74`-byte gap
  `[rsp+0x154..0x1c8]` that contains the tail source
  `[rsp+0x174..0x17c]`. TrioC's hash-path tail is therefore a
  **stale copy**: the slot is written, but with bytes of unknown
  provenance.

### Landing pads repeat the asymmetry

All five callers have a landing-pad block repeating the 0x40-byte
install (same tail slot, exception path only) before `_Unwind_Resume`:
trioA `0x4e6feb3`, double-gate `0x4e85631`, trioB `0x4e85ada`,
gate-like `0x4e866ff`, trioC `0x4e6c7f6`. TrioC additionally has a
match-shaped (0x38-byte) landing-pad install at `0x4e6c7cb` — the
0x38/0x40 asymmetry extends to unwind paths.

## Reproduce

```sh
objdump -d -M intel --start-address=0x4e6fd50 --stop-address=0x4e6fee2 \
  artifacts/node/94/hl-node   # trioA: install reads at 0x4e6fddd..0x4e6fde7
objdump -d -M intel --start-address=0x4e6bcb0 --stop-address=0x4e6c840 \
  artifacts/node/94/hl-node   # trioC: memcpy 0x4e6be08..0x4e6be1a, gate 0x4e6bf53
python3 tools/nonmatch_install_tail_bytes.py --out /tmp/nm-tail
diff -r /tmp/nm-tail research/work-items/RE-004-nonmatch-install-tail-bytes-94 \
  --exclude=README.md --exclude=MANIFEST.sha256
```

Census method (reproducible without the generator): dump a caller FDE
with `objdump -d -M intel` and list every instruction whose destination
operand is the tail slot's stack range; the only hits are the two
install reads. TrioC's memcpy is a PLT call, so it does not appear in a
store grep — check its setup bytes (`lea rdi,[rsp+0x34]`,
`lea rsi,[rsp+0x140]`, `mov edx,0xb8`, `call PLT 0x576dfe0`) instead.

## Deterministic regeneration

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/nonmatch_install_tail_bytes.py --out /tmp/a
PYTHONHASHSEED=99 TZ=Asia/Seoul python3 tools/nonmatch_install_tail_bytes.py --out /tmp/b
diff -r /tmp/a /tmp/b   # exit 0
```

The generator reads only `artifacts/node/94/hl-node`, checks its
SHA-256 first, writes only to `--out`, and performs no execution,
evaluation, disassembly or network access.

## Inferences (separated from observations)

- The 4 unwritten tails (and trioC's null-path tail) hold whatever
  previously occupied those stack slots: stale residue from an earlier
  occupant of the frame, not data any function on the path produced.
  Their runtime contents cannot be determined statically.
- TrioC's hash-path tail is a stale copy, not fresh data: the memcpy
  instruction is real, but its source bytes are themselves unwritten.
- The match path leaves the object's 7th qword at whatever value the
  object held before the install; the packet does not determine that
  prior value.
- The tail bytes are copied verbatim into the object on the non-match
  path (and on unwind via the landing pads), so a consumer reading the
  object's 7th qword after a non-match install sees stale-stack bytes.

## Limitations

- Static analysis only; no node execution, so no runtime tail contents.
- The generator verifies recorded instruction bytes and call targets; it
  does not disassemble, so the "no other store" census rests on the
  documented full-FDE objdump census, not on a generator proof. A
  checker can reproduce the census with the method above.
- Destructor vtable callees were not traced individually; the boundary
  argument is that they receive object-derived pointers only, never a
  caller stack address.
- The trioC hash-map loop body was not traced instruction by
  instruction; only its entry (fall-through from the memcpy), its exits
  to the gate (`0x4e6bf53` via `0x4e6bed4`/`0x4e6bf38`) and its
  back-edges were established — sufficient for the memcpy-before-gate
  claim, not for the loop's own semantics.
- Frame sizes are the `sub rsp` locals sizes; saved-register spill
  slots above each frame are not part of any tail slot.

## Next question

The wider non-tag-5 copy reads: in trioA/double-gate/trioB/gate-like,
the verbatim-copy paths also read decoder-buffer slots the decoder
never wrote (e.g. trioA reads `[rsp+0x1..0x8]` and `[rsp+0x11..0x20]`).
Do those slots have a writer anywhere on their paths, or is the whole
verbatim-copy shape wider than the decoder's 3-field output? That needs
its own per-caller writer census; trioB's vtable path (which does write
`[rsp+0x50..0x70]` via a callee) shows some wider reads are
callee-produced, so the census must separate direct-copy paths from
vtable paths.

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — 5 callers, 4 unwritten + 1 path-dependent tails,
  2 decoders, 3 constructors, 3 destructors, helper, memcpy record
- `installs.tsv` — 5 rows, one per caller
- `tail-writers.tsv` — 16 writer-census rows
- `segments.txt` — 10 tail-covering install-read anchors (explicit
  `tail_read_va instruction_hex tail_start_rsp tail_end_rsp tail_len`
  columns; each row's instruction bytes recover the exact read)
- `MANIFEST.sha256` — digests of the 5 files above
