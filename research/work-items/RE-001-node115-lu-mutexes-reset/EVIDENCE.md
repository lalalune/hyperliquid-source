# RE-001-node115-lu-mutexes-reset: who invokes the #253 reset sweep

- Component ID: control-tree dispatch (`stats.mutexes.reset` leaf) and
  its index-walking dispatcher, node #115 lock-statistics branch.
- Target release and full SHA-256:
  `artifacts/node/115/hl-node`, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`, confirmed by `git fetch`
  before analysis; worktree branch `codex/re-004-calls255-115`.
- Claim status: observation for the dispatcher walk, the tree path,
  and the censuses; inference for the "on demand, not timer" trigger
  conclusion (it rests on the exhaustive negative censuses plus the
  single positive edge, not on a traced `[11, 8, 9]` constructor);
  unresolved for the exact `[11, 8, 9]` constructor site and for leaf
  read-versus-write argument conventions.
- Scope included and excluded: included — the dispatcher FDE, the four
  tree-path nodes, the sweep/dispatcher censuses, and the children
  lists of root/`stats`/`mutexes`. Excluded — the #253 sweep FDE
  itself, the #254 record-reset function, the #251 wait helper, the
  five dispatcher-caller FDEs (surveyed only), sibling tree nodes and
  their subtrees, name strings, the dispatcher's init function and its
  fixed `0x636e340` call, and all timer/lifecycle machinery except
  for the negative census that none of it points at the sweep.

## Reproduce

Working directory: the worktree root (repository checkout at
`05bc2de30`). Tools: `python3` (stdlib only), `objdump`, `readelf`,
`sha256sum`. No execution of the node binary at any point.

- Binary identity:
  `sha256sum artifacts/node/115/hl-node` and
  `stat -c %s artifacts/node/115/hl-node` (105,896,032 bytes).
- FDE bounds:
  `readelf --debug-dump=frames artifacts/node/115/hl-node` (135,313
  FDEs parsed); the dispatcher is `0x63a8ff0..0x63a93ba`, the sweep
  is `0x63a5bf0..0x63a6470` (packet #253, cited only).
- Dispatcher disassembly:
  `objdump -d --start-address=0x63a8ff0 --stop-address=0x63a93ba
  artifacts/node/115/hl-node` (with raw bytes; strict count 232).
- Node dumps: `objdump -s --start-address=<node>
  --stop-address=<node+0x28> artifacts/node/115/hl-node`, plus a
  `.rela.dyn` parse (file offset `0x6be8`, size `0x163cc8`, 60,723
  entries of 24 bytes) for runtime values at RELATIVE slots.
- Censuses: raw `0xe8`/`0xe9` scans over `.text` file range
  `0x1418300..0x63efa00` with rel32 verification; RIP-relative LEA
  scan over `.text` (all REX/`ff`/one-byte-op/movzx/movsx forms);
  `.rela.dyn` and `.rela.plt` (file offset `0x16a8b0`, size
  `0x1a10`, 278 entries) addend scans.
- Tree walk: starting from the root node, read each interior node's
  `+0x10` count and `+0x18` children pointer (runtime values), and
  verify `children + index*0x28` lands on the next path node.
- Static verifier: `python3 tools/node115_mutexes_reset.py`
  (exit 0). Unit tests:
  `python3 tests/test_node115_mutexes_reset.py` (10/10, standalone,
  no binary execution; objdump header line stripped in comparisons
  because it embeds the invoked path).

## Evidence

Coordinate system: `.text` file offset = VA − 0x1000 (re-derived
from program headers: PT_LOAD file offset `0x1418300` ↔ vaddr
`0x1419300`); `.data.rel.ro` file offset = VA − 0x2000;
`.rodata` file offset = VA as-is (`.rodata` addr = offset
`0x430400`). `.bss` (`0x64ffe40..0x6728924`) is not in the file;
only the init-flag address `0x6712140` is cited, never a value.

Raw dispatcher facts (all inside the claimed FDE):

- Entry `0x63a8ff0`: `endbr64`; prologue pushes `r15`, `r14`,
  `r13`, `r12`, `rbp`, `rbx`, `sub $0x48, %rsp`.
- `0x63a904d`: `cmpb $0x0, 0x3690ec(%rip)` → `.bss` `0x6712140`;
  `0x63a9056`: `call 0x63a8240` (init, cited only);
  `0x63a9380`: `mov $0xb, %eax` (init-failure exit).
- `0x63a9063`: `lea 0x64da500(%rip), %r11` (root children);
  `0x63a906d`: `lea 0x64da4c0(%rip), %rax` (root node);
  `0x63a9098`: `cmp 0x64da4d0(%rip), %rcx` (root count 13).
- Walk step, repeated unrolled: `lea (index, index, 4)` then
  `lea (children, index*8)` = child node; `mov 0x18(child), %r11`
  (next children array); bounds check `cmp 0x10(parent), %rcx`.
- Dynamic-node calls: `call *0x8(%r11)` at `0x63a91ab`,
  `0x63a91f9`, `0x63a921d`, `0x63a9242`, `0x63a933f`,
  `0x63a9393`, and `call *0x64da508(%rip)` at `0x63a9366`.
- Completion: `0x63a9258` saves the final node; `0x63a9266`:
  `cmpq $0x0, 0x20(%rsi)` (handler null check); `0x63a92aa`:
  `mov 0x20(%r11), %rax` (handler load); `0x63a92fe`:
  `jmp *%rax` (tail-call with the caller's original arguments).
  Error exit `0x63a91e7`: `mov $0x2, %eax; ret`.
- Padding: `0x63a8fe8..0x63a8ff0` (8 bytes `int3`, after the previous
  FDE ending at `0x63a8fe8`); `0x63a93ba..0x63a93c0` (6 bytes
  `int3`, before the next FDE at `0x63a93c0`).

Raw tree facts (runtime values; file qwords at RELATIVE slots are
placeholders and were replaced by `.rela.dyn` addends):

- Root `0x64da4c0`: file qwords `01 00…` with rela at `+0x08` →
  `0x4376fd` (`''`), `+0x10` = 13, rela at `+0x18` →
  `0x64da500`, `+0x20` = 0.
- `stats` `0x64da6b8`: rela at `+0x08` → `0x44869a`
  (`'stats'`), `+0x10` = 11, rela at `+0x18` → `0x64daaa0`,
  `+0x20` = 0.
- `mutexes` `0x64dabe0`: rela at `+0x08` → `0x4385fa`
  (`'mutexes'`), `+0x10` = 10, rela at `+0x18` → `0x64dac60`,
  `+0x20` = 0.
- `reset` `0x64dadc8`: rela at `+0x08` → `0x440c22`
  (`'reset'`), `+0x10` = 0, `+0x18` = 0, rela at `+0x20` →
  `0x63a5bf0` (the sweep, via slot `0x64dade8`).
- Index arithmetic: `0x64da500 + 11*0x28 = 0x64da6b8`;
  `0x64daaa0 + 8*0x28 = 0x64dabe0`;
  `0x64dac60 + 9*0x28 = 0x64dadc8`.
- Sibling verification (cited only): root children
  `version, epoch, background_thread, max_background_threads, thread,
  config, opt, tcache, arena, arenas, prof, stats, experimental`;
  `stats` children `allocated, active, metadata, metadata_thp,
  resident, mapped, retained, background_thread, mutexes, arenas,
  zero_reallocs`; `mutexes` children `background_thread,
  max_per_bg_thd, ctl, prof, prof_thds_data, prof_dump,
  prof_recent_alloc, prof_recent_dump, prof_stats, reset`.
  Each sibling's kind (interior vs leaf), count, children pointer,
  or handler was read from the same scan; none is claimed.

Census methods and denominators:

- `.text` E8/E9 scans: whole `.text` file range, every site
  rel32-verified (not a raw `0xe8` count — immediates that merely
  look like calls were excluded by the target check).
- LEA scans: raw RIP-relative forms plus a streaming
  `objdump -d --no-show-raw-insn` grep for both the sweep address and
  the dispatcher address (the dispatcher grep found the 54 call
  lines plus the FDE label line only; no `lea` to either target).
- `.rela.dyn`: all 60,723 entries; exactly one addend equals the
  sweep (`0x64dade8`), zero equal the dispatcher. `.rela.plt`:
  all 278 entries; zero equal either target.
- Negative timer/lifecycle evidence: the sweep's inbound set is
  exactly the one rela slot; the dispatcher's inbound set is exactly
  the 54 `E8` sites in five stats-reader FDEs. No `.init_array`
  entry, thread-spawn call, or timer registration references the
  sweep or the dispatcher-with-path-`[11, 8, 9]`; the five caller
  FDEs contain no `$0xb` immediate, so the path is not staged
  literally inside them.
- Analysis completeness: the dispatcher FDE was read in full
  (232 strict instructions); the tree walk was verified at all
  three levels; the censuses cover the whole `.text` and the whole
  relocation tables. The five caller FDEs were NOT read in full
  (only their dispatcher call sites and FDE bounds); the `[11, 8, 9]`
  constructor was NOT isolated. Both limits are stated, not hidden.

## Implementation and comparison

Not yet implemented/measured: this is an observation packet, not a
reconstruction change. No Rust code, Cargo graph, or build
comparison is claimed. The deliverables are the static verifier
(`tools/node115_mutexes_reset.py`, byte reads only, never executes
the binary) and its unit tests
(`tests/test_node115_mutexes_reset.py`, regeneration comparison plus
a tamper control). Helper/data/relocation closure: the verifier
re-derives the tree nodes from file bytes plus `.rela.dyn` addends,
re-runs the `.text` E8/E9 census, re-checks the dispatcher strict
count from the exhibit, and re-runs the disjointness collector
against the merged tree (excluding this packet and excluding
census/cited-only metadata subtrees).

## Results and limitations

- Passed: verifier exit 0; unit tests 10/10 standalone;
  `make verify` exit 0 (tally reported by the run, never copied);
  `make catalogue-check` run and reported honestly (exit 2,
  pre-existing `Stale catalogue: README.md` on a pristine
  `05bc2de30` checkout, not a packet regression).
- Failed: none in the packet's own gates. Full `make test` was not
  attempted (584 test files on the new base; hours-long run liable
  to VM-restart termination); this deviation is disclosed in the
  README and the PR body.
- What remains unknown: the exact `[11, 8, 9]` constructor site;
  whether a name-to-index resolver exists; leaf read-versus-write
  argument conventions; the purpose of the dispatcher's fixed
  `0x636e340` call. None of these changes the trigger answer, which
  follows from the exhaustive negative censuses plus the single
  positive tree edge.
- Next question: which caller constructs the dispatcher index path
  `[11, 8, 9]` for `stats.mutexes.reset` — a name-to-index resolver
  or hardcoded upstream indices — and is the `reset` leaf
  write-only, or can a read dispatch reach it too?
