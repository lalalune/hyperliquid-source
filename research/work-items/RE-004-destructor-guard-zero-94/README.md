# RE-004 destructor guard zero — node #94

## Claim status

**Claimed.** #173's Next question — what fills the destructor loop's
guard slot `[obj+0x198]` for this object, i.e. does the destructor
loop actually run over the pair array on the c3 route, or is it
skipped? — is answered, and the answer corrects #173 on two points:

- **The loop is skipped on the c3 route: the guard is 0.** The
  guard slot in destructor coordinates (`[dtor+0x198]`) is the
  builder-caller output object's `[orig+0x2a0]`, which the sweep
  memcpy fills from `[rsp+0x438]`, which the buffer memcpy fills
  from `[rsp+0x1440]` — a slot the builder caller explicitly
  zeroes (`0x4e7d454`) after briefly holding a hash, and which
  no later store in the builder-caller FDE touches. So
  `cmp [rdi+0x198],0; je 0x37f70ee` takes the skip branch on
  both the forward normal path and the forward unwind path
  (both pass `orig+0x108` to the destructor).
- **Correction to #173: even if the loop ran, it would not walk
  the pair array.** #173 analyzed the destructor as if it
  received the original object. It does not: the forward join
  block does `rbx += 0x108` before calling the destructor, and
  the unwind path does the same. In destructor coordinates the
  pair array (`orig [0x1f0..0x2a0]`) sits at `[0xE8..0x198)` —
  entirely below the loop's first load at `[0x198]`. The walk
  range in original coordinates is `[0x2a0..0x12b0]`, not the
  pair array, and #173's "oc pair loaded at r12 = 0x228
  (`[rbx+0x210]`/`[rbx+0x218]`)" slots are, in original
  coordinates, `[0x318]`/`[0x320]` — `.rodata`-buffer-derived
  qwords, not C3 / element `0x574bd30`.
- **The hinted slot is not the guard.** #173's suggested trace
  (the `[rsp+0x88]` sub-object's +8 field) resolves to
  `0x574d2c0` via constructor `0x4e8a830`, and maps through the
  movups block and the sweep to `[orig+0x198]` = `[dtor+0x90]` —
  below the loop start and below the guard. It is not what the
  `je` tests.

**Not claimed.** No defect, exploitability, or security severity
is claimed. Whether the skip-path sub-destructor at
`[dtor+0x88]` reads `[dtor+0x90]` (the hinted slot's landing
spot) is not traced here. Destructor behavior for objects other
than the c3-route object is out of scope.

## Scope

Included:

- The guard-value chain on the c3 route: builder caller FDE
  `0x4e7d360..0x4e7d678` (792 B), c3 FDE
  `0x326e540..0x326f350` (3600 B), forward FDE
  `0x37fb9e0..0x37fd846` (7782 B), destructor FDE
  `0x37f7070..0x37f721a` (426 B), constructor `0x4e8a830`
  (`0x4e8a830..0x4e8a9e2`, 434 B).
- 19 guard-chain rows in `guard-chain.tsv`, 7 coordinate rows
  in `coord-map.tsv`, 18 byte segments in `segments.txt`
  (11 claim segments, 97 bytes; 7 anchor segments, 75 bytes,
  #173's claims re-cited with attribution).
- The GOT-indirect call census for this route: exactly 1 GOT
  slot (`0x5773ff8`, `.rela.dyn` entry 75886, RELATIVE,
  addend `0x4e7d360`), file bytes 0.

Excluded:

- The destructor's post-skip sub-destructors (`0x37f5c80` at
  `[dtor+0x88]` etc.) beyond their call sites; the forward
  mid-section tag-dispatch blocks beyond the no-store-to-`rbx`
  census; the `0x574be20` object and its 6 neighborhood
  references (still open from #172); the runtime initializer
  of `.data` objects `0x5786838`/`0x5786858` (still open from
  #169); the #157–#173 subjects and #1543's fixed-eight topic.

## Observations

### The guard chain: seven links, value 0

| link | site | fact |
|---|---|---|
| prologue zero | `0x4e7d36c` | first prologue `[rsp]=0` lands at `[final rsp+0x1440]` |
| hash store | `0x4e7d3dd` | `mov [rsp+0x1440],r14` (transient hash) |
| zero store | `0x4e7d454` | `mov [rsp+0x1440],0x0` (final normal-path value) |
| buffer memcpy | `0x4e7d4a8` | `memcpy([rsp+0x438],[rsp+0x1440],0x1000)` → `[rsp+0x438] = 0` |
| sweep memcpy | `0x4e7d5bf` | `memcpy([rbx+0x108],[rsp+0x2a0],0x1198)` → `[rbx+0x2a0] = 0` |
| forward +0x108 | `0x37fd237` / `0x37fd829` | both paths shift `rbx` by `0x108` before the destructor call |
| guard test | `0x37f707e` | `cmp [rdi+0x198],0; je 0x37f70ee` with `[rdi+0x198] = [orig+0x2a0] = 0` |

No other store to `[rsp+0x1440]` exists in the builder-caller
FDE: the only references are the `lea` for the hash multiply
(`0x4e7d3ad`), the two stores above, the memcpy source `lea`
(`0x4e7d4b0`), and the landing-pad cleanup `lea`
(`0x4e7d64a`, unwind path only). The intervening callees
(`0x4e80440`, `0x4e77920`, `0x4e8a830`, builder `0x4e72b40`)
each receive exactly one pointer (their `rdi` sub-object) and
no pointer to `[rsp+0x1440]`; the sub-objects are freshly
constructed in this FDE. The movups block (`0x4e7d4c0..`)
writes only `[rsp+0x2a0..0x388]`; the pair copy writes
`[rsp+0x388..0x438)` (exclusive end); neither touches
`[rsp+0x438]` after the buffer memcpy, and the sweep only
reads the stack. c3 writes nothing to the object between the
GOT call and the forward call; the forward mid-section
contains no store to `[rbx+...]` at all (its only `[rbx]`
access is the marker read at `0x37fbbab`).

### The coordinate correction

The destructor receives `rdi = rbx` after `rbx += 0x108`
(normal path `0x37fd237` → call `0x37fd272`; unwind path
`0x37fd829` → call `0x37fd833`). So every destructor offset
maps to an original offset 0x108 higher:

| destructor slot | original slot | content | verdict |
|---|---|---|---|
| `[0x198]` guard | `[0x2a0]` | 0 (chain above) | loop skipped |
| `[0x198]` walk start (hypothetical) | `[0x2a0]` | just past pair array end | walk would miss the array |
| `[0x1a0]` walk first element (hypothetical) | `[0x2a8]` | `.rodata` head copy | not a table element |
| `[0x210]`/`[0x218]` (#173 "oc pair") | `[0x318]`/`[0x320]` | `.rodata`-buffer qwords | not C3 / `0x574bd30` |
| pair array `[0x1f0..0x2a0]` | `[0xE8..0x198)` in dtor coords | 11 pairs incl. oc pair | entirely below loop start |

The loop itself (guard aside) runs `r12` from `0x1b0` to
`0x11b0` in steps of `0x10`, loading `[rbx+r12-0x18]` (cell)
and `[rbx+r12-0x10]` (element) — first iteration
`[0x198]`/`[0x1a0]`. In original coordinates that walk is
`[0x2a0..0x12b0]`: the sweep-buffer region, whose qwords come
from the `[rsp+0x1440..0x2440]` buffer (`[rsp+0x1440] = 0`,
`[rsp+0x1448..0x1c48]` = `.rodata 0x574c318` copy). No
iteration touches a table element.

### The hinted slot resolves elsewhere

The `[rsp+0x88]` sub-object is built by `0x4e8a830`, whose
`[rbx+0x8]` store (`0x4e8a981`) writes `rcx` =
`lea 0x574d2c0` (`0x4e8a97a`). The movups block copies
`[rsp+0x88..0x98]` to `[rsp+0x328..0x338]`, so
`[rsp+0x330]` = `0x574d2c0`; the sweep maps `[rsp+0x330]`
to `[orig+0x198]`, i.e. `[dtor+0x90]`. That slot is below
both the guard (`[dtor+0x198]`) and the loop start, and is
not tested by the `je`. (The skip path does call a
sub-destructor at `[dtor+0x88]` (`0x37f7127`), whose object
starts at `[dtor+0x88]` and thus spans `[dtor+0x90]` — but
that callee is not traced here, so no read of the hinted
slot is claimed.)

### The skip path head

On the skip branch (`0x37f70ee`) the destructor calls
`0x3bc8560` with `rdi = rbx`, then frees the
`[rbx]`/`[rbx+0x8]` vector if nonzero and runs
sub-destructors at `[rbx+0x18]`, `[rbx+0x48]`, `[rbx+0x88]`
(dtor coords; original `[0x120]`, `[0x150]`, `[0x190]`).
None of those offsets lies in the pair array
(`orig [0x1f0..0x2a0]`), so the skip path also never touches
a pair.

## Inferences (separated from observations)

- On the c3 route the pair array is never read by the
  destructor at all: the loop that would read it is skipped
  (guard 0), and the skip path's offsets avoid the array.
  #173's "reads-but-skips" characterization of the
  destructor on this route is superseded: it neither reads
  nor dispatches, because it never enters the loop.
- The shape is route-specific: this verdict is for the
  c3-route object only (builder-caller output + 0x108). The
  destructor is generic; other callers passing other
  objects may take the loop branch. No claim is made about
  them.

## Limitations

- The "no other store to `[rsp+0x1440]`" census rests on
  the documented full-FDE objdump census of the builder
  caller plus the single-pointer-argument structure of its
  callees; the generator verifies every recorded
  instruction byte but does not disassemble.
- The skip-path sub-destructors are not traced; in
  particular no claim is made about whether `0x37f5c80`
  (at `[dtor+0x88]`) reads `[dtor+0x90]`.
- The forward mid-section tag-dispatch blocks are censused
  only for stores to the input object (none found); their
  own semantics are not analyzed.
- Static analysis only; no node execution, so no runtime
  values beyond the statically forced guard (0) are claimed.

## Reproduce

Target: node #94 only (91,774,280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
Static analysis only; the node binary is never executed.

Code address A maps to file offset A − 0x1000 (`.text`);
`.got` uses VA − 0x2000; `.rela.dyn` entries are 24 bytes at
file offset `0x6bc0` (entry 75886 is the GOT slot). The
generator fails loudly on any digest, relocation, or byte
mismatch.

```sh
# guard test and skip branch (destructor)
objdump -d -M intel --start-address=0x37f707e --stop-address=0x37f7088 \
  artifacts/node/94/hl-node
# zero store and buffer memcpy (builder caller)
objdump -d -M intel --start-address=0x4e7d454 --stop-address=0x4e7d460 \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e7d4a8 --stop-address=0x4e7d4c0 \
  artifacts/node/94/hl-node
# forward join shift and destructor call
objdump -d -M intel --start-address=0x37fd237 --stop-address=0x37fd23e \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x37fd26f --stop-address=0x37fd277 \
  artifacts/node/94/hl-node
# GOT relocation (entry 75886)
readelf -r -W artifacts/node/94/hl-node | grep 5773ff8
python3 tools/destructor_guard_zero.py --out /tmp/dg-zero
diff -r /tmp/dg-zero research/work-items/RE-004-destructor-guard-zero-94 \
  --exclude=README.md --exclude=MANIFEST.sha256
```

Deterministic regeneration (the generator writes only to --out):

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/destructor_guard_zero.py --out /tmp/a
PYTHONHASHSEED=99 TZ=Asia/Seoul python3 tools/destructor_guard_zero.py --out /tmp/b
diff -r /tmp/a /tmp/b   # exit 0
```

## Next question

- Does the skip-path sub-destructor at `[dtor+0x88]`
  (`0x37f5c80`) read `[dtor+0x90]` — i.e. does anything on
  the c3 route ever consume the hinted `[rsp+0x88]+8` value
  (`0x574d2c0`) after it lands at `[orig+0x198]`?
- What is the `0x574be20` object, and what do its 6
  neighborhood references (`0x4e77xxx` region, carried from
  #172) do with it?
- Which runtime initializer fills `.data` objects `0x5786838`
  and `0x5786858` (carried from #169), and what does the
  `[r14+0x8]` callee family write?

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — node binding, FDE extents, GOT relocation, guard
  derivation, correction table, counts
- `guard-chain.tsv` — 19 rows, one per chain link
- `coord-map.tsv` — 7 rows, destructor-to-original coordinate mapping
- `segments.txt` — 18 rows: 11 claim segments (97 bytes) + 7 anchor
  segments (75 bytes, #173's claims re-cited), each with start..end,
  length == end − start, file offset, and SHA-256
- `MANIFEST.sha256` — digests of the 5 files above
