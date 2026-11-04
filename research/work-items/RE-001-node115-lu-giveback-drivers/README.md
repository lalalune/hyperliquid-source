# RE-001-node115-lu-giveback-drivers

## Question

Packet #244's next question: what the give-back caller FDEs
establish before calling the #243 give-back function
(`0x63d8e70`), and which `[block+0x12]` / `[block+0x13]`
flag states they set — deciding who drives give-back and
under what conditions. One of the three FDEs named there
(`0x63b8820..0x63b8d85`) was already decoded by merged
packet #232 (see the correction below), so this packet
decodes the remaining drivers: A, B, and D.

## Answer, in one paragraph

Three undecoded FDEs drive give-back — and none of them sets
`[block+0x12]`. The give-back's removal gate (`+0x12`) is
inherited from the block's producer, never armed by these
drivers: across all three FDEs there is not one store to a
`+0x12` displacement. What the drivers do set, on every path,
is `[block+0x13]` — but only **after** the give-back call
returns, as post-call bookkeeping before the immediately
following `0x63d9070` call: either `0` (word store, which
also zeroes `+0x14`) when `testl $0xffff00, 0x20(block)`
is nonzero, or `([block+0xb0] != [block+0x68])` via `setne`
when that test is zero, with `+0x14 := 1` in the setne case.
So the `+0x13` value give-back sees at each of the 7
claimed sites is the block's incoming state (C's site is
#232's, cited only), and the `+0x13` value written here
is what the block carries into the `0x63d9070` call that
follows. The drivers decoded here are: A, a bounded drain
loop with 5 give-back sites; B, a list walker with 1 site
that calls A when its list empties; and D, a counted-loop
allocator with 1 site that calls A afterwards. A is
therefore the shared drain, driven by B and D (and by C,
already decoded by #232, cited only).

## Correction to #243 (read this first)

#243's census grouped the 8 give-back call sites into 3
FDEs, putting site `0x63b8296` under FDE
`0x63b7ef0..0x63b8157` (B). That grouping is wrong:
`.eh_frame` shows `0x63b8296` lives in a fourth FDE,
`0x63b81b0..0x63b8517` (D, 871 bytes, `push %r15` entry,
single `ret` at `0x63b84d4`), which sits between B's end
(`0x63b8157`, 9 bytes of `int3` padding, then a 75-byte
wrapper FDE at `0x63b8160` that calls B) and the tiny
`0x63b8520` FDE. D is C's near-twin: same
allocate → class-search → give-back → consume →
bookkeeping → register → list-insert cycle, differing
only in that D loops over a caller-supplied count while C
is a gated single shot. #243's site list itself (all 8
addresses, all rel32-verified) was correct; only the
FDE attribution of `0x63b8296` was off, and it is
corrected here. The fan-in is therefore 4 driver FDEs,
not 3.

## The uniform call contract (all 8 sites)

Give-back's first argument is uniformly `context+0x140`:

- A: `r14 := (%rsp)`, where `(%rsp)` was set at entry to
  `r15+0x140` (entry `rsi` is the context object).
- B: `r14 := rbx+0x140` (entry `rsi` is the context object).
- D: `r12 := rbx+0x140`.

The block argument varies by driver (below), but the
first argument does not. The give-back call sites,
rel32-verified: A `0x63b7af7`, `0x63b7c30`, `0x63b7cef`,
`0x63b7d8b`, `0x63b7e0a`; B `0x63b808e`; D `0x63b8296`
(C's site `0x63b892f` is #232's, cited only).

## The flag rule (verified at every site)

No driver writes `[block+0x12]` before its give-back call,
and no driver writes `[block+0x12]` at all — the verifier
scans all three FDEs' disassembly for any `0x12(`
displacement store and finds none (the only `0x12`
occurrences are the `0x120`/`0x128` vtable calls, which
are not `+0x12` stores). Every `[block+0x13]` store in
all three FDEs occurs after a give-back call, in this
shape:

1. `testl $0xffff00, 0x20(block)`: if nonzero, write
   `+0x13 := 0` by word store (also zeroes `+0x14`).
2. If zero, `setne +0x13` from the comparison
   `[block+0xb0]` vs `[block+0x68]`; then, when the
   size/overflow checks pass, `+0x14 := 1` (and, on the
   paths that take the `*0x128` call, `+0x18 :=` the
   call's out-value).

The `+0x13` stores, by site:

| After site | Zero form | Setne form |
|---|---|---|
| A `0x63b7af7` | `0x63b7b06` word, `ebp=0` | — (this path always zeroes) |
| A `0x63b7c30` | `0x63b7d1b` word, `r12d=0` | `0x63b7c6e` |
| A `0x63b7d8b` | `0x63b7d99` word, `r10d=0` | — |
| A `0x63b7e0a` | `0x63b7e8b` word, `ebx=0` | `0x63b7e43` |
| B `0x63b808e` | `0x63b80b3` word, `r9d=0` | `0x63b7fd1` |
| D `0x63b8296` | `0x63b842b` word, `r11d=0` | `0x63b8364` |

A's site `0x63b7cef` (site 3) rejoins site 2's post-call
path at `0x63b7c35`, so it shares site 2's flag stores.
In every case the flag stores are followed, in program
order, by a `0x63d9070` call with `(first-arg, block)` —
so the written `+0x13` is consumed downstream of
give-back, not by the give-back call that precedes it.

Neighbouring flag bytes written in the same post-call
sequences (stated, not decoded as a flag protocol):
`+0x11 := 0` then `:= 1` around A's sites 1–2,
`+0x21 := 1` then `:= 0` around A's sites 1–2,
`+0x22 := 1` then `:= 0` around A's sites 4–5.
`+0x14` is written by the setne/zero rule above.

## Driver A: the drain loop (5 sites)

FDE `0x63b7900..0x63b7ee6` (1510 bytes, `push %r15`
entry — no `endbr64` — single `ret` at `0x63b7ab5`).
Entry: `rdi` saved at `0x38(%rsp)` (reused as a later
call argument), `rsi` = context (`r15`). Loop bound
`0x30(%rsp)` is `16` when the entry `dl` flag is `0`
and `-1` (unbounded) when it is nonzero; counter
`0x8(%rsp)` starts at `0` and increments after each
`0x63d9070` call. Two block sources feed the loop: the
`0x63d94a0` getter (cited only, called twice per
iteration on the main path) and the `0x63d9460` getter
(cited only, on the third path).

- Site 1 (`0x63b7af7`): block fresh from `0x63d9460`.
  After give-back: `+0x21 := 1`, `+0x13 := 0` (word),
  `+0x11 := 0`, then `0x63d9070`, then a `0x63bb7e0`
  call (cited only) and a per-node walk loop.
- Sites 2/3 (`0x63b7c30` / `0x63b7cef`): the main loop
  body, split on the `0x17(%rsp)` byte (zero → site 2
  directly; nonzero → site 3, which first bumps the
  `context+0x1640` counter and then rejoins site 2's
  post-call path). After give-back: `0x63bc300` (cited
  only), `+0x21 := 0`, `+0x11 := 1`, then the
  setne/zero `+0x13` rule, then `0x63d9070`,
  counter++, loop.
- Sites 4/5 (`0x63b7d8b` / `0x63b7e0a`): the third path,
  block from `0x63d94a0`. Site 4 is followed by
  `+0x13 := 0`, `+0x22 := 1`, `0x63d9070`, unlock,
  re-lock, then site 5 with the same block; site 5 is
  followed by a `0x63bc430` call (cited only),
  `+0x22 := 0`, the setne/zero `+0x13` rule,
  `0x63d9070`, counter++, loop-back check.

A's loop is the shared drain: B and D call A
(`0x63b7900`) at their tails (B `0x63b80d8`, D
`0x63b8480`); C also calls A (documented in #232,
cited only).

## Driver B: the list walker (1 site)

FDE `0x63b7ef0..0x63b8157` (615 bytes, `endbr64`
entry, zero `ret` — its only exit is a tail `jmp` to
`pthread_mutex_unlock@plt` at `0x63b8125`). Entry:
`rdi` = first-arg (`r13`), `rsi` = context (`rbx`),
`rdx` = pointer to a list head (`r12`), `rcx` saved.
First it walks a `+0x28`-linked list, calling
`0x63ae980` (cited only) per node while page-masking
each node's `+0x8` field and clearing bit 15 of its
`+0x0` field. Then, under the context `+0x80` mutex, it
unlinks nodes one by one from the `(%r12)` list (with
the single-node case zeroing the head), calls
`0x63b59e0` (cited only) and then give-back at
`0x63b808e` with the block `rbp := [node+0x18]`, then
calls `0x63bb330` (cited only) and applies the
setne/zero `+0x13` rule before `0x63d9070`, looping
until the list empties — at which point it calls A
with `(r13, rbx, edx=0)`, then the `0x63d94a0` getter,
and returns via the mutex-unlock tail jump.

## Driver C: already decoded by #232 (cited only)

FDE `0x63b8820..0x63b8d85` is packet #232's
"class-minimum consumer" (merged PR #2644): it
already claims this FDE's bytes, including its
give-back site at `0x63b892f`, and its next question
explicitly invited decoding the loop caller D. This
packet therefore claims no byte of C; C is cited
here only as the fourth give-back driver, and its
call to A is documented in #232. The flag rule above
is established on A, B, and D; no C byte is
exhibited or re-claimed.

## Driver D: the counted twin of C (1 site)

FDE `0x63b81b0..0x63b8517` (871 bytes, `push %r15`
entry — no `endbr64` — single `ret` at `0x63b84d4`,
returning the loop count in `rbp`). Same cycle as C —
`0x63b5840`, class search `0x63d9340` → block `r14`,
give-back at `0x63b8296`, `0x63ba680`, field surgery,
`0x63ae2b0` test, setne/zero `+0x13` rule,
`0x63d9070`, list insertion — but looping over a
caller-supplied count (`r8`, saved at `0x30(%rsp)`,
against counter `rbp`) instead of C's entry gates, and
returning the count when the loop finishes, after a
final call to A plus the `0x63d94a0` getter. The
give-back site and its post-call zero-arm counter
(`0x63b82a2..0x63b82b4`) are byte-for-byte the same
shape as C's (`0x63b893b..0x63b894d`).

## What this decides

- Give-back's `+0x12` removal gate is never armed by
  its drivers: the only known `+0x12 := 1` writer in
  this chain is the #238 handoff, and the removal entry
  itself clears it. A block arrives at give-back with
  whatever `+0x12` its producer left.
- Give-back's `+0x13` tail gate is likewise inherited,
  not set, by these drivers at call time: every `+0x13`
  write here happens after the call, for the downstream
  `0x63d9070` call.
- The `+0x13` value written after give-back is a
  function of the block itself: `0` when the block's
  `+0x20` word has high bits set, else
  `([block+0xb0] != [block+0x68])`.
- The driver topology is settled: B and D each feed A
  (C does too, per #232, cited only), and A is the
  loop that drains blocks through give-back
  repeatedly.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame` (A
  `0x63b7900..0x63b7ee6`, B `0x63b7ef0..0x63b8157`, D
  `0x63b81b0..0x63b8517`); `int3` padding: A→B 10
  bytes, B→wrapper 9 bytes, wrapper→D 5 bytes,
  D→tiny 9 bytes. (C's bounds, `0x63b8820..0x63b8d85`,
  are #232's, cited only.)
  Static analysis only; the binary was never executed.
- 5 exhibits, 207 bytes, 51 strict instructions
  (strict = mnemonic-line count: address + bytes field
  + tab + mnemonic; objdump byte-continuation lines
  excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `gbA_site1` | `0x63b7aea..0x63b7b0e` | 36 | 10 | A site 1: args, call, `+0x21:=1`, `+0x13:=0`, `+0x11:=0` |
| `gbA_tail` | `0x63b7c6e..0x63b7c9a` | 44 | 11 | A site 2 tail: `+0x13` setne, `+0x14:=1` |
| `gbB_site` | `0x63b8080..0x63b80a3` | 35 | 9 | B site: args, call, post-call callee |
| `gbD_site` | `0x63b8290..0x63b82b8` | 40 | 9 | D site: args, call, zero-arm counter |
| `gbD_tail` | `0x63b8364..0x63b8398` | 52 | 12 | D tail: `+0x13` setne, `+0x14:=1`, `+0x18` store |

- The remaining flag stores (A `0x63b7d1b`,
  `0x63b7d99`, `0x63b7e43`, `0x63b7e8b`; B
  `0x63b7fd1`, `0x63b80b3`; D `0x63b842b`) are
  verified by the static verifier's key-byte checks,
  not exhibited, to keep the packet at 16 files.
- Census: direct `E8` call sites to `0x63d8e70`: 8
  (listed above, all rel32- and objdump-confirmed).
  Direct `E9` jump sites: 0. Rip-relative `LEA`
  sites: 0. `.rela.dyn` addends equal to `0x63d8e70`:
  0 of 60,723 entries. Jump targets: all inside the
  owning FDE except B's tail `jmp` to
  `pthread_mutex_unlock@plt` (its exit). Ret sites:
  A 1, B 0, D 1.
- Disjointness: these FDEs and exhibits overlap no
  claimed range from packets #183–#244 (including
  #232's claimed C ranges, which this packet does not
  touch) and no other contributor's topic, addresses,
  or tables. The
  give-back function, the class search, the getters,
  the `0x63d9070` callee, the handoff, the register,
  the gate, the driver, and the allocator thunk are
  cited by address, not claimed here.

## Corrections to earlier packets

- **#243 corrected (grouping only).** Its 8 site
  addresses were all correct, but site `0x63b8296`
  belongs to FDE D (`0x63b81b0..0x63b8517`), not to
  FDE B. The driver count is 4 FDEs, not 3 — of which
  C was already decoded (see #232 below).
- **#232 confirmed and completed in part.** Its
  class-minimum consumer (C) is the fourth give-back
  driver; its next question explicitly invited D,
  which is decoded here. No byte of C is re-claimed.
- **#244 confirmed, with a scope correction.** Its
  next question named three caller FDEs, but one of
  them (C) was already decoded by #232; the remaining
  drivers decoded here are A, B, and D. The
  post-remove tail target is untouched here.
- **#242 confirmed.** The removal entry's only caller
  remains the give-back function; these drivers call
  give-back, never the removal entry directly.
- **#241 confirmed.** The class remove is reached from
  here only indirectly, through give-back, never
  directly.
- **#240 confirmed.** The probe's empty verdict is not
  re-tested here; these drivers test the `+0x20` word
  and the `+0xb0`/`+0x68` comparison instead.
- **#239 confirmed.** The class insert's chains are not
  touched here.
- **#238 confirmed and completed.** The handoff's flag
  (`[block+0x12] := 1`) is the flag these drivers
  never write: it is the inherited removal-gate state
  give-back tests.
- **#237 confirmed.** The register's size-class entries
  are not the slots updated here.
- **#236 confirmed.** A consume-stamped block
  (`[block+0x68] == 0`) reaches give-back on the
  drivers' paths and books the zero-arm counter
  afterwards in C and D.
- **#235 confirmed.** The gate's paths reach these
  drivers only indirectly (the gate FDE `0x63b85f0`
  is cited only, not claimed here).
- **#234 confirmed.** The driver's gate-block path runs
  gate, then register, then handoff; give-back driving
  runs through these three FDEs, not the driver path.
- **#233 confirmed.** The loop caller is not involved
  with these drivers.
- **#232 confirmed.** The single-shot caller (C) is
  itself a give-back driver, already decoded there;
  this packet claims none of its bytes.
- **#216 confirmed.** The allocator thunk `0x636b370`
  is the gate's allocator; these drivers never call it.

## Unresolved

- The full set of `[block+0x12]` writers across the
  binary: within these three FDEs there are none, but
  no whole-binary census of `+0x12` stores is made
  here, so writers beyond the #238 handoff are not
  excluded.
- What the `0x63d9070` callee does with the block
  after the drivers set `+0x13` — whether it reads
  `+0x13` or passes the block on. This is #246's
  question.
- The domain meaning of the `+0x11` / `+0x21` /
  `+0x22` bytes beyond their post-call set/clear
  pattern in A.
- Who calls C and D (their own callers are not
  censused here), and what establishes C's gate
  inputs (`rdx`, `rcx`, `r8b`) and D's count (`r8`).
- The domain meaning of the `+0x20` word's high bits
  (`$0xffff00` test) beyond their role in the
  setne/zero branch.
- `.bss` contents are runtime-filled and not readable
  from the file; nothing here depends on them.

## Next question (#246)

Decode the post-call callee FDE `0x63d9070..0x63d9337`
end to end: what it does with the (first-arg, block)
pair it receives from these three drivers after they
set `+0x13` — whether it reads `+0x13`, what it
establishes in return, and how it relates to the #237
register — deciding where the flag written here is
consumed.

## Verification

- `tools/node115_lu_giveback_drivers.py` static
  verifier: exit 0 ("all checks passed") — SHA/size,
  exhibit bytes, strict counts, FDE bounds, entry
  bytes, ret sites, 8 call rel32s, key flag-store
  bytes, jump targets internal except B's PLT tail
  jump, full census, neighbour disjointness, MANIFEST
  coverage (15 entries).
- `tests/test_node115_lu_giveback_drivers.py`: 10/10
  pass.
- `make verify`: exit 0 (559 manifests, 7169 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a
  pristine `05bc2de30` checkout, so this is
  pre-existing upstream staleness from the merge wave,
  not a packet regression.
- Full `make test`: not attempted on the new base (584
  files; a full run takes hours and was already shown
  in #234 to be liable to VM-restart termination).
  This packet's own file passes 10/10 standalone.

## Files (16)

- `research/work-items/RE-001-node115-lu-giveback-drivers/README.md`
- `research/work-items/RE-001-node115-lu-giveback-drivers/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-giveback-drivers/records.json`
- `research/work-items/RE-001-node115-lu-giveback-drivers/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-giveback-drivers/gbA_site1.hex`
- `research/work-items/RE-001-node115-lu-giveback-drivers/gbA_site1.objdump.txt`
- `research/work-items/RE-001-node115-lu-giveback-drivers/gbA_tail.hex`
- `research/work-items/RE-001-node115-lu-giveback-drivers/gbA_tail.objdump.txt`
- `research/work-items/RE-001-node115-lu-giveback-drivers/gbB_site.hex`
- `research/work-items/RE-001-node115-lu-giveback-drivers/gbB_site.objdump.txt`
- `research/work-items/RE-001-node115-lu-giveback-drivers/gbD_site.hex`
- `research/work-items/RE-001-node115-lu-giveback-drivers/gbD_site.objdump.txt`
- `research/work-items/RE-001-node115-lu-giveback-drivers/gbD_tail.hex`
- `research/work-items/RE-001-node115-lu-giveback-drivers/gbD_tail.objdump.txt`
- `tools/node115_lu_giveback_drivers.py`
- `tests/test_node115_lu_giveback_drivers.py`
