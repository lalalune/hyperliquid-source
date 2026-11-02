# RE-004 hinted-slot consumption — node #94

## Claim status

**Claimed.** #174's Next question (a) — does the skip-path
sub-destructor at `[dtor+0x88]` (`0x37f5c80`) read `[dtor+0x90]`,
i.e. does anything on the c3 route ever consume the hinted
`[rsp+0x88]+8` value (`0x574d2c0`) after it lands at
`[orig+0x198]`? — is answered:

- **Yes, conditionally.** Nothing on the c3 route reads
  `[dtor+0x90]` directly, but the shared drop helper
  `0x4e79840` — reached from `0x37f5c80`'s first branch via
  GOT slot `0x5774108` — loads `[rdi+0x8]` unconditionally
  at entry (`0x4e79848`), and on the `0x37f5c80` route that
  load IS `[dtor+0x90]`. The helper then dereferences the
  loaded value as a (function-pointer, base, length) header
  triple: `[H+0x0]`, `[H+0x8]`, `[H+0x10]`.
- **The condition is a runtime refcount.** The helper call
  fires only if the first member's refcount
  (`[[dtor+0x88]]`) reaches zero in `0x37f5c80`'s
  `lock dec; jne` gate (`0x37f5c87..0x37f5c8e`). If the
  refcount does not hit zero, the hinted slot is never
  read on this route. The gate value is a heap runtime
  value and is not statically determined, so the verdict
  is conditional, not absolute.
- **For this header the indirect call is skipped.**
  The header at `0x574d2c0` holds `(0, 0, 1)`, so the
  helper's `H[0]` call gate (`test rax,rax; je`) takes
  the skip branch, while `H[2] = 1` still feeds the
  delete-size computation on the helper's second leg
  (if the second refcount also hits zero).

**Not claimed.** No defect, exploitability, or security
severity is claimed. Whether the first member's refcount
ever reaches zero on the c3 route at runtime is not
determined (static analysis only). The helper's full
type semantics (what struct the header triple belongs
to) are not identified. Destructor behavior for objects
other than the c3-route object is out of scope.

## Scope

Included:

- The skip-path sub-destructor trio: `0x37f59f0`
  (`0x37f59f0..0x37f5a84`, 148 B),
  `0x37f5bb0` (`0x37f5bb0..0x37f5c71`, 193 B),
  `0x37f5c80` (`0x37f5c80..0x37f5d9b`, 283 B) —
  their direct read offsets, their 0x10-stride shape,
  and their GOT-indirect first-branch calls.
- The shared drop helper `0x4e79840`
  (`0x4e79840..0x4e798d8`, 152 B): all 8 recorded
  operations, including the unconditional `[rdi+0x8]`
  load and the header-triple dereferences.
- The GOT census: 10 distinct GOT slots, all
  RELATIVE with addend `0x4e79840`, all with zero
  file bytes; zero direct E8 callers of the helper;
  zero RIP-relative references to either function.
- The c3-route consumption census (10 rows in
  `route-census.tsv`): vector teardown `0x3bc8560`
  (235 B), vector free, the three sub-destructors,
  the final jump target `0x37f57c0` (556 B), the
  forward FDE (7782 B), c3's two `[r12+0x198]`
  stores, and the destructor guard test.
- 16 byte segments in `segments.txt` (11 claim
  segments, 175 bytes; 5 anchor segments, 59 bytes,
  #173/#174 claims re-cited with attribution).

Excluded:

- The `0x574be20` object and its 6 neighborhood
  references (still open from #172); the runtime
  initializer of `.data` objects `0x5786838` /
  `0x5786858` (still open from #169); the
  `[r14+0x8]` callee family beyond the helper
  identified here; the #157–#174 subjects and
  #1543's fixed-eight topic.

## Observations

### The three sub-destructors are 0x10-stride refcount walks

Each sub-destructor copies `rdi` to `rbx` and then walks
its members in 0x10 steps, loading each member pointer
and doing `lock dec` on the pointee's refcount, calling
a GOT-indirect helper only when the count hits zero:

| sub-destructor | entry (dtor coords) | direct reads | helper `[rdi+0x8]` maps to |
|---|---|---|---|
| `0x37f59f0` | `+0x18` | `[sub+0x0,0x10,0x20]` | `dtor+0x20` |
| `0x37f5bb0` | `+0x48` | `[sub+0x0,0x10,0x20,0x30]` | `dtor+0x50` |
| `0x37f5c80` | `+0x88` | `[sub+0x0,0x10,0x20,0x30,0x40,0x50]` | `dtor+0x90` — the hinted slot |

13 direct reads total, all at 0x10 stride. No
sub-destructor ever reads its own `+8` slot directly:
the `+8` slots fall exactly between the walk steps.
The only `+8` read in the whole family is the shared
helper's `[rdi+0x8]` load — which is why the hinted
slot's fate depends entirely on which sub-object the
helper receives.

### The shared helper reads [rdi+0x8] unconditionally

`0x4e79840` (152 B), in order:

| step | site | fact |
|---|---|---|
| load-P | `0x4e79845` | `rbx = [rdi]` |
| load-H | `0x4e79848` | `r14 = [rdi+0x8]` — unconditional, before any branch |
| load-H0 | `0x4e7984c` | `rax = [r14]` (call target) |
| load-H2 | `0x4e7984f` | `r15 = [r14+0x10]` (length) |
| call-gate | `0x4e79853..0x4e7986a` | `test rax,rax; je` skips the `call rax` when `H[0] = 0` |
| P-counter | `0x4e79870` | `lock dec [rbx+0x8]`; returns unless zero |
| load-H1 | `0x4e79877` | `rcx = [r14+0x8]` (size base) |
| delete | `0x4e798ae..0x4e798b6` | `operator delete` on `rbx` (GOT `0x576e010`) |

On the `0x37f5c80` route, `rdi` is the `dtor+0x88`
sub-object, so load-H reads `[dtor+0x90]` =
`0x574d2c0`. On the sibling routes the same load
reads `dtor+0x20` (`0x37f59f0`) and `dtor+0x50`
(`0x37f5bb0`) — never the hinted slot.

### The header triple at 0x574d2c0 is (0, 0, 1)

File bytes (`.data.rel.ro`, VA − 0x2000; no
relocation entry targets any of the three slots, so
file values are final):

| slot | value | used as |
|---|---|---|
| `[0x574d2c0]` (H[0]) | `0` | indirect-call target — call skipped |
| `[0x574d2c8]` (H[1]) | `0` | delete-size base |
| `[0x574d2d0]` (H[2]) | `1` | length → `max(8, 1) = 8`, aligned size 16 |

### The gate: first member refcount

`0x37f5c80`'s first branch:

```
0x37f5c87: mov rax,[rdi]        ; rax = [dtor+0x88] pointer
0x37f5c8a: lock dec [rax]       ; decrement its refcount
0x37f5c8e: jne 0x37f5c99        ; nonzero -> skip the helper call
0x37f5c90: mov rdi,rbx          ; rdi = sub-object
0x37f5c93: call [0x5774108]     ; -> helper 0x4e79840
```

The helper call — and therefore the hinted-slot read —
happens exactly when that refcount reaches zero. The
refcount lives in a heap object and is not statically
determined.

### Reachability: the destructor is the sole caller

- `0x37f5c80` has exactly 2 E8 call sites in all of
  `.text`: `0x37f7127` (skip-path epilogue) and
  `0x37f71f2` (loop-path epilogue), both inside
  destructor `0x37f7070`. Zero RIP-relative references.
- `0x4e79840` has zero direct E8 callers and zero
  RIP-relative references in all of `.text`. It is
  reached only through the 10 GOT slots listed above
  (3 for `0x37f59f0`, 3 for `0x37f5bb0` with one
  shared, 5 for `0x37f5c80`), all RELATIVE with
  addend `0x4e79840`.
- The sibling sub-destructors are likewise called
  only from the destructor's two epilogues
  (`0x37f59f0` ← `0x37f7112`/`0x37f71dd`;
  `0x37f5bb0` ← `0x37f711b`/`0x37f71e6`).

### Checked negatives on the c3 route

- Vector teardown `0x3bc8560` reads `[rdi+0x8]`
  (array base) and `[rdi+0x10]` (count) of the
  destructor object, then walks array pairs — never
  `[rdi+0x90]`.
- Vector free reads `[rbx]` and `[rbx+0x8]` only.
- Final jump target `0x37f57c0` (receives
  `dtor+0xe8`) contains no `[rdi-0x58]` read in its
  full 556 B FDE.
- Forward FDE contains no `[rbx+0x198]` read in its
  full 7782 B (its only `[rbx]` access of note is the
  `[rbx+0x12a0]` marker read).
- c3's two `[r12+0x198]` stores (`0x326e908`,
  `0x326f115`) are same-displacement-different-base:
  `r12` was rebased to `[rsp+0x368]` at `0x326e8c3`
  and to the popped caller value at `0x326efdc`,
  so neither store touches the builder-caller
  object's hinted slot, and neither is a read.
- The destructor guard test reads `[rdi+0x198]`
  (`orig+0x2a0`), not the hinted `orig+0x198`.

## Inferences (separated from observations)

- On the c3 route the hinted value `0x574d2c0` is
  consumed if and only if the first member's
  refcount reaches zero during the skip-path
  teardown. The consumption is a pointer dereference
  (header triple), not a dispatch: for this header
  the indirect call is skipped and only the length
  feeds the delete-size math.
- #174's open question is therefore closed with a
  conditional yes, not a no: the slot is not dead
  (it is loaded and dereferenced on the zero path),
  but it is not unconditionally live either (the
  nonzero path never touches it).
- The 0x10-stride shape of the whole sub-destructor
  family explains why the `+8` slot survived all
  prior censuses: direct walks step over it, and
  only the shared helper's entry load reaches it.

## Limitations

- The "no other store / no other read" censuses rest
  on the documented full-FDE objdump censuses of the
  listed functions plus the exact E8 / RIP-relative /
  GOT scans; the generator verifies every recorded
  instruction byte but does not disassemble.
- The refcount gate value is a runtime heap value;
  no claim is made about whether it ever reaches
  zero on the c3 route in practice.
- The helper's header-triple struct type is not
  identified; only its load/call/delete behavior is
  claimed.
- Static analysis only; no node execution, so no
  runtime values beyond the statically forced header
  triple (0, 0, 1) are claimed.

## Reproduce

Target: node #94 only (91,774,280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
Static analysis only; the node binary is never executed.

Code address A maps to file offset A − 0x1000 (`.text`);
`.data.rel.ro` and `.got` use VA − 0x2000; `.rela.dyn`
entries are 24 bytes at file offset `0x6bc0`. The
generator fails loudly on any digest, relocation, or
byte mismatch.

```sh
# sub-destructor first branch + helper call (0x37f5c80)
objdump -d -M intel --start-address=0x37f5c87 --stop-address=0x37f5c99 \
  artifacts/node/94/hl-node
# helper entry loads (0x4e79840)
objdump -d -M intel --start-address=0x4e79845 --stop-address=0x4e79853 \
  artifacts/node/94/hl-node
# GOT relocations (all 10 slots -> 0x4e79840)
readelf -r -W artifacts/node/94/hl-node | grep -E "57740e0|57740e8|57740f0|57740f8|5774100|5774108|5774110|5774118|5774120|5774128"
python3 tools/hinted_slot_consumption.py --out /tmp/hsc
diff -r /tmp/hsc research/work-items/RE-004-hinted-slot-consumption-94 \
  --exclude=README.md --exclude=MANIFEST.sha256
```

Deterministic regeneration (the generator writes only to --out):

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/hinted_slot_consumption.py --out /tmp/a
PYTHONHASHSEED=99 TZ=Asia/Seoul python3 tools/hinted_slot_consumption.py --out /tmp/b
diff -r /tmp/a /tmp/b   # exit 0
```

## Next question

- Does the first member's refcount (`[[dtor+0x88]]`)
  ever reach zero on the c3 route at runtime — i.e.
  is the conditional consumption live in practice?
  (Needs execution; out of static scope.)
- What struct is the helper's header triple (fn,
  base, length), and what allocates the `0x574d2c0`
  header?
- What is the `0x574be20` object, and what do its 6
  neighborhood references (`0x4e77xxx` region,
  carried from #172) do with it?
- Which runtime initializer fills `.data` objects
  `0x5786838` and `0x5786858` (carried from #169)?

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — node binding, FDE extents, GOT census, caller
  census, hinted-slot header triple, verdict
- `subdtor-walk.tsv` — 3 rows, one per skip-path sub-destructor
- `helper-consumption.tsv` — 8 rows, one per helper operation
- `route-census.tsv` — 10 rows, one per c3-route candidate
- `segments.txt` — 16 rows: 11 claim segments (175 bytes) + 5 anchor
  segments (59 bytes, #173/#174 claims re-cited), each with start..end,
  length == end − start, file offset, and SHA-256
- `MANIFEST.sha256` — digests of the 6 files above
