# RE-001-node115-lu-wait-helper: the lu lock-wait helper

- Component ID: RE-001-node115-lu-wait-helper
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de30` (confirmed
  before analysis)
- Claim status: observation for all byte-level claims; inference for the
  statistic-field names and the spin-limit reading; unresolved for the
  flag clearer, the runtime global values, and the ticket discipline
- Scope included and excluded: the single FDE `0x63bf680..0x63bf7ee`
  (366 bytes) is claimed; the small qword helpers, the now-nanoseconds
  helper, the max-now helper, the merge callers, and all other call
  sites are cited only

## Reproduce

Static analysis only; the binary was never executed. Worktree
`~/workspace/hl-wt-calls251-115`, branch `codex/re-004-calls251-115`,
base `05bc2de30`. Coordinate conversion: `.text` file offset =
VA − 0x1000 (re-derived from program headers, PT_LOAD off=0x1418300
↔ vaddr=0x1419300); `.data.rel.ro`/`.got` = VA − 0x2000;
`.rodata` = VA as-is. FDE bounds from `.eh_frame` (PC-relative sdata4,
CIE augmentation `zR`, encoding byte `0x1b`).

Commands (exit codes read directly, never through a pipe):
`python3 tools/node115_lu_wait_helper.py` (exit 0),
`python3 -m unittest tests.test_node115_lu_wait_helper` (10/10),
`make verify` (exit 0), `make catalogue-check` (exit 2, pre-existing
`Stale catalogue: README.md` on the new base). Full `make test` not
attempted per the parent task's rule (584 files on the new base).

## Evidence

- FDE `0x63bf680..0x63bf7ee`, 366 bytes, `endbr64` entry, one `ret`
  site at `0x63bf71d`, `int3` padding 9 bytes before and 2 bytes after.
- Entry: `r12 := rdi` (arg), `rbp := arg+0x40` (mutex), pushes
  `r14/r13/r12/rbp/rbx`, stack canary at `0x18(%rsp)`.
- Spin gate 1: `.bss` word at `0x6511730` (runtime-filled, value not
  claimed); `== 1` jumps straight to the slow path at `0x63bf720`.
- Spin gate 2: `.data` qword at `0x64ffc98`; loop continues while it
  equals -1 or exceeds the spin count in `rbx`, else slow path.
- Spin body: `pause`; `[arg+0x68]` nonzero rechecks the limit;
  otherwise `pthread_mutex_trylock@plt` on `arg+0x40` (site
  `0x63bf6ee`); success increments `[arg+0x18]` and returns.
- Slow path: now-nanoseconds helper `0x63bfcf0` (site `0x63bf730`,
  `CLOCK_MONOTONIC`) writes the start time; copy to the deadline
  slot; `lock xadd` ticket on `[arg+0x24]` (site bytes at
  `0x63bf745`); trylock (site `0x63bf750`); on failure blocking
  `pthread_mutex_lock@plt` (site `0x63bf75c`); `[arg+0x68] := 1`;
  waiter decrement; indirect call through GOT slot `0x64df1e8`
  (RELATIVE, resolves to `0x63bfa70`, max-now) on the deadline slot;
  elapsed subtract, slow-count bump, total add, max store, ticket
  high-water, then the shared success exit.
- Internal calls (12 sites, rel32-verified): trylock ×2, blocking
  lock ×1, now helper ×1, qword copy ×3, qword subtract ×1, qword
  add ×1, qword compare ×1, indirect max-now ×1, stack-check
  failure ×1 (failure path only).
- Argument record fields proved by stores: `+0x00` total waited,
  `+0x08` max single wait, `+0x10` slow-path count, `+0x18`
  success count, `+0x20` high-water ticket, `+0x24` live waiters,
  `+0x40` mutex, `+0x68` contended flag.
- Caller-B fit: record at `object+0xb0` → mutex `object+0xf0`,
  flag `object+0x118`; record at `object+0x40` → mutex
  `object+0x80`, flag `object+0xa8`. Caller B clears both flags on
  its success exit; this function never clears the flag.
- Census: direct `E8` sites 474 (objdump-mnemonic confirmed,
  all rel32-verified), including #250's `0x63b92e3` and `0x63b92fb`;
  `E9` 0; rip-relative `LEA` 0; `.rela.dyn` addends 0 of 60,723.
- Disjointness: 952 unique ranges checked (merged tree +
  prior worktree records, deduplicated by real path with ranges
  deduplicated as a set, own slug excluded), 0 overlaps.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed for
this helper in this packet. The packet is evidence only: exhibits,
records, a static verifier, and unit tests (regeneration comparison
+ tamper control).

## Results and limitations

- Verifier exit 0; unit tests 10/10; `make verify` exit 0
  (559 manifests, 7169 entries); `make catalogue-check` exit 2
  (pre-existing upstream staleness, not a packet regression).
- Unknown: the flag clearer beyond caller B's exit; the runtime
  spin-disable and spin-limit values; whether tickets order waiters
  or only count them; the identities of the helper's other callers;
  the domain names of the statistic fields beyond their update
  pattern.
- Next question (#252): survey the helper's other direct callers
  for waiter records with a different layout or purpose than
  caller B's two records.
