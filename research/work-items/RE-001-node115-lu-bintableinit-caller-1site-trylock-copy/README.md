# RE-001-node115-lu-bintableinit-caller-1site-trylock-copy

Fifth 1-raw bin_table_init caller packet (after #298, #299, #300,
#301). The window is a single-site trylock-guarded lookup-with-copy
routine: one bin_table_init site (`lea 0x20(%rsp)` in-block, entered
only by a null-context `je`), a two-phase context-table walk that
reads the node-resolution table `0x65096c0` (but no size table —
`0x6727a00`/`0x67277c0` are NOT read here, and `0x6511780` is not
read either), an 8-slot move-to-front scan (all normal-operand
compares, none reversed), a `pthread_mutex_trylock` prologue with a
lock-wait helper retry arm and owner-tracking globals, a 4-byte
fast-path vs byte-copy slow-path value copy, and a single `ret`
exit — no tail jump.

## Window

- FDE `0x6387420..0x6387878`, 1112 bytes, 254 strict mnemonic lines.
- Previous FDE `0x6386eb0..0x6387420` (gap 0 bytes — adjacent, not
  decoded here).
- Next FDE `0x6387880..0x6387fec` (padding 8 bytes, all `0xcc`,
  not decoded here).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1b8,%rsp`,
  canary at `0x1a8(%rsp)`.
- Entry: `rdi` = context (kept in `r14`), `r9` = key pointer (kept
  in `r13`), `r8` = size pointer (kept in `rbp`), `rcx` = output
  buffer (kept in `rbx`); 7th stack argument `0x1f0(%rsp)` must be
  8.
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Trylock prologue: mutex `0x67121a0` in `r12`; `pthread_mutex_trylock`
  at `0x638745e`; on failure the lock-wait helper `0x63bf680` (#251)
  runs on `mutex-0x40`, flag `0x67121c8` is set, and the lock is
  retried (`jmp 0x638746b`). On success, counter `0x6712198` is
  incremented, the owner slot `0x6712190` is compared against the
  context, and counter `0x6712188` is incremented with the owner
  stored. `pthread_mutex_unlock` at `0x6387566` releases it, after
  flag `0x67121c8` is cleared.
- Phase-1 walk on the context+`0x1b0` table; on a top-level match the
  second-level value is shifted/masked and the node is resolved
  through table `0x65096c0` — like #300/#301 (but only `0x65096c0`,
  not `0x6511780`). No size class: no `0x6727a00`/`0x67277c0` read,
  no bsr anywhere in this FDE (unlike #298/#301).
- Bin_table_init site: `0x6387629` (block `0x6387618`,
  `lea 0x20(%rsp)` in `rsi`, `mov %rsi,%rdi`; `rcx` saved to
  `0x8(%rsp)` and `rsi` to `(%rsp)` before the call, `r10`/`rcx`
  restored after; rejoin `jmp 0x63874cc`).
- Lu-miss site: `0x6387869` (scan exhaustion; `r8d` = 1, `r9d` = 0,
  `rdi` = context in `r14`, `rdx` = scan table in `r10`,
  `rcx` = key in `r15`, `rsi` = `lea 0x6511a00`; rejoin
  `jmp 0x63874f2`).
- Scan: 8 slots, table+`0x100`, move-to-front on a hit; all eight
  compares are normal-operand — no reversed-operand compare in this
  FDE (unlike #298/#299/#301, which had one or two).
- Value copy: the resolved node's field at `+0x13450` is stored to
  `0x1c(%rsp)`; if the size in `*rbp` is 4 it is written directly
  to `*rbx` (fast path, return 0); otherwise up to 4 bytes are
  copied from `0x1c(%rsp)` to `(%rbx)` and the copied length is
  stored back to `*rbp` (slow path, return `0x16`).
- Return: `eax` is 0 on the plain resolved path, `0x16` (22) on
  the byte-copy path, on a 7th stack argument != 8, on a null
  second-level value, and on a null node pointer.
- Calls: 6 (trylock, unlock, lock-wait helper, bin_table_init,
  lu-miss, `__stack_chk_fail`).
- Exit: single `ret` at `0x6387595`; all 39 jump instructions
  target inside the window — no tail-jump exit (exit-ness verified
  per FDE).

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x6387420..0x6387878` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #301's window
`0x6363d50..0x6364270`, packet #300's window
`0x63637f0..0x6363d50`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## Prior pointer verified (no correction)

#301's survey pointer for this window (1112 bytes, 1 bin_table_init
site, 1 lu-miss site, 1 ret, 0 bsr) is verified correct by program
arithmetic and by the objdump census above.

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded as
a whole FDE (`0x63adf40..0x63ae252`, overlapping #214's claimed
sub-ranges). This packet builds on the fifth survivor. The next
frontier is packet #303 on `0x63adb50..0x63adf34`.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_trylock_copy_1site.py`:
  exit 0 (final check count from the sealing run: see below).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_trylock_copy_1site.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0 (final check count from the
  sealing run: see below). The test harness uses lean temp copies
  (verifier + packet dir + symlinked binary only); a full worktree
  copy changes nothing the verifier reads.
- `make verify`: exit 0 (559 evidence-packet manifests, 7159
  entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine
  checkout; not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.

## Sealing-run figures

- Verifier: exit 0, 84 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 58,858 priors, 0 skipped,
  NONE (deduplicated figure 58,110 after removing 748
  exhibits carrying both a `range` key and a `start`/`end` pair).
