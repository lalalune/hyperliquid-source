# RE-001-node115-lu-wait-callers

## Question

Packet #251's next question: survey the other direct callers of the
lu wait helper FDE `0x63bf680` — which call sites pass waiter
records with a different layout or purpose than packet #250 caller
B's two records — deciding whether this helper serves one lock
family or many.

## Answer

One helper, many lock families, one record layout. All 474 direct
call sites were surveyed (grouped by enclosing caller FDE and
classified by argument shape); no caller was found passing a record
whose mutex is not at `+0x40` or whose flag is not at `+0x68`.
Four caller FDEs were decoded in depth, and each cross-checks the
same internal offsets at a different embedding offset: a record
embedded at `+0x18`, one at `+0x38`, one at `+0x28a8`, and global
records. The embedding offset varies; the layout does not. The
helper is shared lock-wait infrastructure, not a family-specific
function — but the survey does not prove the layout for the 381
caller FDEs whose internals were not decoded (see Scope).

## The shared pattern

Every decoded caller follows the same trylock-fail fallback:

1. `pthread_mutex_trylock` on the record's mutex (`record+0x40`).
2. On failure, call the wait helper `0x63bf680` on the record.
3. On return, set the record's flag byte (`record+0x68`) to 1.
4. On the unlock path, clear the same flag byte to 0, then call
   `pthread_mutex_unlock` on the record's mutex.

Packet #251 proved the helper itself sets `+0x68` after a blocking
acquisition and never clears it; these callers set it again after
any wait return (including the spin-fast path, where the helper
does not set it) and clear it when unlocking. Caller B of #250
fits: it clears both flags on its success exit.

## Census: all 474 sites

- Direct `E8` call sites to `0x63bf680`: 474. Method: raw `E8`
  scan over `.text` file offsets `0x1418300..0x63f0ba0`, every
  site rel32-verified; every site additionally confirmed as an
  objdump `call` row to `0x63bf680` while disassembling its
  enclosing FDE individually. Direct `E9` sites: 0 (raw scan).
  Rip-relative `LEA` sites to the helper: 0 (raw scan).
  `.rela.dyn` addends equal to `0x63bf680`: 0 of 60,723.
- Caller FDEs: 385 (via `.eh_frame`). Sites per FDE: 1 site in
  348 FDEs, 2 in 19, 3 in 9, 4 in 4, 5 in 1, 7 in 2, 8 in 1, 18 in
  1 (the largest, `0x63a5bf0..0x63a6470`). 348+38+27+16+5+14+8+18
  = 474.
- The two #250 caller-B sites (`0x63b92e3`, `0x63b92fb`) and the
  three sites in packet #232's FDE (`0x63b8ce5`, `0x63b8d43`,
  `0x63b8d59`, FDE `0x63b8820..0x63b8d85`) are counted here but
  no byte of either FDE is claimed here.

## Argument shapes (linear-predecessor classification)

For each site, the nearest preceding instruction writing `rdi`
within the enclosing FDE (max 40 instructions back, objdump
comment suffixes stripped) was classified. This is a linear
predecessor, not a proved dataflow fact — control-flow merges
are not resolved.

| Shape | Sites | Reading |
|---|---|---|
| `lea rdi, [reg+0x40]` | 302 | Record embedded at `+0x40` of an enclosing object (r15: 177, r14: 82, r12: 23, r13: 10, rbp: 7, rbx: 3) |
| `lea rdi, [reg+other]` | 4 | Records at `+0x38` (x2), `+0x18`, `+0x28a8` — decoded below |
| `lea rdi, [rip+...]` (global) | 13 | 9 distinct `.bss` globals (see below) |
| `mov rdi, reg` | 131 | Pointer passed through or computed in a register; provenance not traced |
| `mov rdi, [mem]` | 24 | Pointer loaded from a stack slot or memory; provenance not traced |

302+4+13+131+24 = 474.

Global records (13 sites, 9 distinct `.bss` addresses — all in
`.bss` `0x64ffe40..0x6728924`, so their contents are
runtime-filled and not readable from the file): `0x6509620`,
`0x65116c0`, `0x6711ac0`, `0x67145a0` (3 sites), `0x6714620`
(3 sites), `0x6714520`, `0x67146a0`, `0x67158a0`, `0x67276e0`.

## Representative callers decoded

### Global records — FDE `0x63cf9d0..0x63cff1b` (1355 bytes, `endbr64` entry)

Exhibit `g_wait` shows both wait sequences: `lea` the global
record (`0x67145a0`, then `0x6714520`), call the helper, then
`movb $1` to the record's flag byte (`0x6714608` =
`0x67145a0+0x68`; `0x6714588` = `0x6714520+0x68`). The same FDE
trylocks the matching mutexes first (`0x67145e0` =
`0x67145a0+0x40`; `0x6714560` = `0x6714520+0x40`) and, on a
surveyed (not exhibited) unlock path, clears the flag
(`0x63cfeb4`: `movb $0, 0x68(%r9)`), takes the mutex
(`0x63cfeb9`: `lea 0x40(%r9), %rdi`), and unlocks
(`0x63cfebd` -> `0x63f0b70`).

### Record at `+0x38` — FDE `0x6364280..0x6364342` (194 bytes, `endbr64` entry)

Exhibit `r38_try`: `lea 0x78(%rbx), %r14` then trylock — `0x78`
= `0x38+0x40`, the record's mutex. Exhibit `r38_wait`: the
trylock-fail target `lea 0x38(%rbx), %rdi`, call the helper,
`movb $1, 0xa0(%rbx)` — `0xa0` = `0x38+0x68`, the record's
flag. The unlock path clears the same byte (`0x6364308`:
`movb $0, 0xa0(%rbx)`) before unlocking the mutex in `r14`.

### Record at `+0x18` — FDE `0x63b5a40..0x63b5b3d` (253 bytes, `endbr64` entry)

`rbp` is loaded from `[rsi+0x08]`. Exhibit `r18_try`: `lea
0x58(%rbp), %rdi` then trylock — `0x58` = `0x18+0x40`.
Exhibit `r18_wait`: the fail target `lea 0x18(%rbp), %rdi`,
call the helper, `movb $1, 0x80(%rbp)` — `0x80` =
`0x18+0x68`. The unlock path clears `0x80` of the same object
(`0x63b5b03`) before unlocking `+0x58` (`0x63b5b0a`,
`0x63b5b0e`).

### Record at `+0x28a8` — FDE `0x63ec7a0..0x63ec900` (352 bytes, push-`r14` entry, no `endbr64`)

`rbp` is loaded from `[rsi+0x28]`. Exhibit `r28_wait`: `lea
0x28a8(%rbp), %rdi`, call the helper, `movb $1, 0x2910(%rbp)`
— `0x2910` = `0x28a8+0x68`. Surveyed (not exhibited) trylock
setup: `lea 0x28e8(%rbp), %r13` (`0x63ec7b2`) then trylock
(`0x63ec7bc`) — `0x28e8` = `0x28a8+0x40`. The unlock path
clears `0x2910` (`0x63ec872`) before unlocking (`0x63ec879`).

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame` (PC-relative sdata4
  encoding); entry bytes checked by the verifier. Static analysis
  only; the binary was never executed.
- 6 exhibits, 122 bytes, 23 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `g_wait` | `0x63cfeeb..0x63cff1b` | 48 | 8 | Two global wait sequences: lea record, call, flag set, jmp |
| `r38_try` | `0x63642c3..0x63642cf` | 12 | 3 | Trylock on the `+0x38` record's mutex at `+0x78` |
| `r38_wait` | `0x6364330..0x6364342` | 18 | 4 | Wait on the `+0x38` record, flag set at `+0xa0` |
| `r18_try` | `0x63b5a58..0x63b5a61` | 9 | 2 | Trylock on the `+0x18` record's mutex at `+0x58` |
| `r18_wait` | `0x63b5b28..0x63b5b38` | 16 | 3 | Wait on the `+0x18` record, flag set at `+0x80` |
| `r28_wait` | `0x63ec890..0x63ec8a3` | 19 | 3 | Wait on the `+0x28a8` record, flag set at `+0x2910` |

- Claimed bytes are only the 6 exhibits. The `r28` trylock
  setup and the global unlock path are surveyed observations
  (addresses and bytes recorded in `records.json`, checked by
  the verifier's byte reads), not claimed exhibits.
- Disjointness: the exhibits overlap no claimed range from
  packets #183–#251 (962 unique exhibit/FDE ranges checked
  across the merged tree and the prior worktree records,
  deduplicated by real path with ranges deduplicated as a set,
  own slug excluded, 0 overlaps) and no other contributor's
  topic, addresses, or tables. The helper FDE, the merge
  callers, the merge, the give-back, the reset, the insert, the
  register, the re-register, the class-min FDE, and the other
  decoded callers are cited by address, not claimed here.
- Scope honesty: the helper's 474 sites cannot all be decoded in
  one light packet. What was done: all 474 sites grouped by FDE
  and classified by argument shape; 4 FDEs decoded in depth.
  What was NOT done: the internals of the other 381 caller
  FDEs, the provenance of the 131 `mov reg` / 24 `mov [mem]`
  pointers, any post-wait statistic reads, and the domain
  identity of any lock. No exhaustive-coverage claim is made,
  and no defect is claimed: the finding is that no layout
  deviation was found where looked.

## Corrections to earlier packets

- **#251 confirmed and extended.** Its open question — who
  calls the helper at its other 472 sites, and whether any
  caller passes a record whose mutex is not at `+0x40` — is
  answered as far as this survey goes: all 474 sites surveyed,
  4 caller families cross-checked, none with a different
  internal layout. #251's flag-clear question is partly
  answered: the decoded callers clear the `+0x68` flag on
  their unlock paths (global, `+0x38`, `+0x18`, `+0x28a8`
  families), not only caller B's exit.
- **#250 confirmed.** Caller B's two records (`object+0xb0`,
  `object+0x40`) are two of the 474 surveyed sites; the
  `+0x40`-embedding shape (302 sites) is the common case, and
  caller B's second record is an instance of it.
- **#232 confirmed.** Its FDE's 3 helper sites are counted in
  the census; nothing of that FDE is re-claimed here.
- **#249, #248, #247, #246, #243 confirmed.** Nothing of theirs
  is re-claimed here.

## Unresolved

- Whether any of the 381 not-deeply-decoded caller FDEs passes
  a record with different internal offsets — no counterexample
  was found, but only 4 FDEs were cross-checked, so this is
  not proved for all 474 sites.
- The provenance of the 131 register-passed and 24
  memory-loaded argument pointers: which objects they point
  into, and whether any points at a record with a different
  layout.
- Whether any caller reads the statistic fields (`+0x00..+0x24`)
  after the wait returns, and what any caller does with them.
- The domain identity of each lock family (which subsystem each
  caller belongs to) — no function names are claimed.
- The runtime values of the `.bss` global records, and what
  clears the flag besides the decoded unlock paths.
- `.bss` contents are runtime-filled and not readable from the
  file; nothing here depends on them.

## Next question (#253)

Trace the provenance of the register-passed and memory-loaded
arguments: pick the largest caller FDE (`0x63a5bf0..0x63a6470`,
18 helper sites) and decode where its record pointers come
from — deciding whether the `mov`-shape callers pass the same
record type through, or a different one.

## Verification

- `tools/node115_lu_wait_callers.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict
  counts, cited-FDE entry bytes, exhibit call rel32s, surveyed
  cross-check bytes, offset arithmetic, full raw census,
  caller-FDE grouping, neighbour disjointness, MANIFEST
  coverage (17 entries).
- `tests/test_node115_lu_wait_callers.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7171 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout (verified for #242; base unchanged
  since), so this is pre-existing upstream staleness from
  the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone. Note: the worktree's `AGENTS.md`
  says to run `make verify test catalogue-check`, but the
  parent task's explicit no-full-`make test` rule outranks
  it; the deviation is disclosed here, as in #245–#251.

## Files (18)

- `research/work-items/RE-001-node115-lu-wait-callers/README.md`
- `research/work-items/RE-001-node115-lu-wait-callers/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-wait-callers/records.json`
- `research/work-items/RE-001-node115-lu-wait-callers/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-wait-callers/g_wait.hex`
- `research/work-items/RE-001-node115-lu-wait-callers/g_wait.objdump.txt`
- `research/work-items/RE-001-node115-lu-wait-callers/r38_try.hex`
- `research/work-items/RE-001-node115-lu-wait-callers/r38_try.objdump.txt`
- `research/work-items/RE-001-node115-lu-wait-callers/r38_wait.hex`
- `research/work-items/RE-001-node115-lu-wait-callers/r38_wait.objdump.txt`
- `research/work-items/RE-001-node115-lu-wait-callers/r18_try.hex`
- `research/work-items/RE-001-node115-lu-wait-callers/r18_try.objdump.txt`
- `research/work-items/RE-001-node115-lu-wait-callers/r18_wait.hex`
- `research/work-items/RE-001-node115-lu-wait-callers/r18_wait.objdump.txt`
- `research/work-items/RE-001-node115-lu-wait-callers/r28_wait.hex`
- `research/work-items/RE-001-node115-lu-wait-callers/r28_wait.objdump.txt`
- `tools/node115_lu_wait_callers.py`
- `tests/test_node115_lu_wait_callers.py`
