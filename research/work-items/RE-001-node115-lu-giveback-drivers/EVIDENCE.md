# RE-001-node115-lu-giveback-drivers: give-back drivers

- Component ID: RE-001-node115-lu-giveback-drivers
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes, `artifacts/node/115/hl-node`)
- Source commit / reference commit: upstream main `05bc2de30`
  (confirmed by fetch before analysis; worktree HEAD identical)
- Claim status: observation for all byte-level claims below;
  inference for the "consumed downstream" reading of `+0x13`
  (program order, not a read of the callee); unresolved for
  the items listed at the end of the README
- Scope included and excluded: included — the three driver
  FDEs `0x63b7900..0x63b7ee6`, `0x63b7ef0..0x63b8157`,
  `0x63b81b0..0x63b8517`, their 7 give-back call sites,
  and their post-call flag stores. The fourth driver FDE
  (`0x63b8820..0x63b8d85`, site `0x63b892f`) is packet
  #232's (merged PR #2644), cited only, not claimed here.
  Excluded — the give-back function itself (#243), the
  class search (#230), the getters, the `0x63d9070` callee,
  and all other callees, which are cited by address only.

## Reproduce

Working directory: a worktree of lalalune/hyperliquid-source
at `05bc2de30` (this packet's worktree:
`~/workspace/hl-wt-calls245-115`, branch
`codex/re-004-calls245-115`). Tools: GNU objdump 2.42,
Python 3.12.3, git-lfs 3.4.1. No execution of the binary;
no side effects beyond reading files.

- `sha256sum artifacts/node/115/hl-node` →
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- `objdump -d --start-address=0x63b7900 --stop-address=0x63b7ee6 artifacts/node/115/hl-node`
  (and the analogous ranges for B and D) → the three FDE
  disassemblies this packet traces.
- `python3 tools/node115_lu_giveback_drivers.py` → exit 0,
  "all checks passed".
- `python3 -m unittest tests.test_node115_lu_giveback_drivers`
  → 10/10 pass.
- `make verify` → exit 0 (559 manifests, 7171 entries).
- `make catalogue-check` → exit 2, `Stale catalogue:
  README.md`, identical on a pristine `05bc2de30`
  checkout (verified for #242; base unchanged since).

## Evidence

Coordinate system: `.text` VA minus `0x1000` equals file
offset (program-header derived: PT_LOAD off `0x1418300`
↔ vaddr `0x1419300`); `.rodata` VA as-is; `.got` slots
are zero-filled in the file, so the GOT census uses
`.rela.dyn` addends (60,723 entries, 0 equal to
`0x63d8e70`). FDE bounds are `.eh_frame` bounds, not
endbr64 scans: A starts with `push %r15` and D with
`push %r15` (no `endbr64`), B starts with
`endbr64` (C, cited only, also starts with
`endbr64`). The preceding tiny wrapper FDE
(`0x63b8160..0x63b81ab`, which calls B) is a separate
function and is not claimed.

Give-back call sites, all `E8` with rel32 to `0x63d8e70`,
objdump-confirmed: `0x63b7af7`, `0x63b7c30`,
`0x63b7cef`, `0x63b7d8b`, `0x63b7e0a` (A);
`0x63b808e` (B); `0x63b8296` (D); `0x63b892f` (C,
#232's, cited only). First argument at every site
is `context+0x140` (A: `(%rsp)` set to `r15+0x140`;
B: `rbx+0x140`; D: `rbx+0x140`).

Flag stores, all post-call, key-byte verified:
setne `+0x13` at `0x63b7c6e`, `0x63b7e43`,
`0x63b7fd1`, `0x63b8364`; zero-word `+0x13` at
`0x63b7b06`, `0x63b7d1b`, `0x63b7d99`, `0x63b7e8b`,
`0x63b80b3`, `0x63b842b`. Zero `+0x12(`
displacement stores across all three FDEs (the only
`0x12` occurrences are `0x120`/`0x128` vtable calls).
Jump targets: all inside the owning FDE except B's
tail `jmp` to `pthread_mutex_unlock@plt` at
`0x63b8125`, which is B's exit (B has zero `ret`).
Ret sites: A `0x63b7ab5`, D `0x63b84d4` (returning
the loop count in `rbp`).

Raw disassembly and per-exhibit hex are kept beside
this record (`gb*.hex`, `gb*.objdump.txt`); the
records file is machine-readable (`records.json`).
Analysis was complete for the three FDEs' give-back
paths and flag stores; the bodies of the cited callees
were not decoded here.

## Implementation and comparison

Not yet implemented/measured: no reconstructed code is
claimed from this packet. The packet is evidence only,
for a later implementation pass.

## Results and limitations

Metrics with denominators: 5 exhibits, 207 bytes, 51
strict instructions; 7/7 give-back call sites in the
claimed FDEs confirmed (plus #232's C site, cited
only); 10/10 key flag-store byte sequences confirmed;
0 `+0x12` stores in 3 FDEs; 0 overlaps against prior
packets #183–#244. Passed: verifier exit 0, unit
10/10, `make verify` exit 0. Failed (pre-existing,
not a regression): `make catalogue-check` exit 2,
`Stale catalogue: README.md`. Remaining gaps: the
`+0x12` writer census beyond these FDEs, the
`0x63d9070` callee's use of `+0x13`, the callers of D,
and the domain meanings of `+0x11`/`+0x21`/`+0x22`
and of the `+0x20` high-bits test.

Next question (#246): decode the post-call callee FDE
`0x63d9070..0x63d9337` end to end — what it does with
the (first-arg, block) pair after the drivers set
`+0x13`, and where the flag written here is consumed.
