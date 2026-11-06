# RE-001-node115-lu-value-leaves-bin: value leaves, bin setup, interval consumer, gate callees

- Component ID: RE-001-node115-lu-value-leaves-bin
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`
  (105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation for all exhibited bytes, census counts, and
  branch structure; inference for the named roles of globals whose
  identities the file alone does not determine (stated per item);
  unresolved for the items listed at the end.
- Scope included and excluded: included — 5 leaf handlers, 2 bin-setup
  callees (full FDEs), 1 consumer window, 4 gate callee FDEs, caller
  censuses for all of them. Excluded — the remaining 171 leaves, the
  rest of the consumer FDE beyond the exhibited window, the internals
  of the named-but-undecoded callees (`0x63bf840`, `0x63c4bf0`,
  `0x6364420`, `0x63cf8c0`, `0x636b370`, `0x63bf680`, `0x63bf970`).

## Reproduce

Worktree `~/workspace/hl-wt-calls261-115`, branch
`codex/re-004-calls261-115`, at the upstream commit above (fetched
and confirmed before analysis; main clone HEAD untouched at
`2993e46`). Static analysis only; the binary was never executed.

Leaf handlers come from the packet #257 control-tree census
(`~/workspace/scratch-hl257/tree.json`, 204 leaves): each leaf name
maps to a node address, and the handler is the `.rela.dyn` RELATIVE
addend at node+0x20 (verified with `readelf -r` for all 5 leaves
here). FDE bounds come from the packet #260 `.eh_frame` table
(CIE zR, sdata4 encoding 0x1b), not from endbr64 scanning.
Disassembly: `objdump -d --start-address=<va>
--stop-address=<va> artifacts/node/115/hl-node` (the ELF's own
`.text` mapping; VA-to-file-offset is VA - 0x1000, re-derived from
the program headers: PT_LOAD off=0x1418300 ↔ vaddr=0x1419300).
`.rodata` constants use VA-as-is. Caller censuses: full-binary
capstone disassembly over all 135,313 FDEs (18,827,581
instructions), cross-checked by a raw `.text` scan for E8/E9 rel32
targets with identical counts (the verifier re-runs the raw scan).

`.hex` exhibit files contain raw binary bytes, not hex text (packet
#255's format); the verifier, tests, and MANIFEST all treat them as
raw.

## Evidence

### Leaf handlers

`opt/prof` (`0x63737c0..0x6373846`) and `opt/tcache`
(`0x63721c0..0x6372246`) are the same 134B template: stack canary,
eax := 1, `or newp, newlen; jne -> return 1` (write refusal), then
the value byte is staged on the stack (`[0x6713606]` for opt/prof,
`[0x64ffdf8]` for opt/tcache) and the read contract runs: oldp or
oldlenp absent -> 0; `*oldlenp` == 1 -> `*oldp` = byte, 0; else a
1-byte copy guarded by (`*oldlenp` != 0), `*oldlenp` := that flag,
0x16. `config/stats` (`0x6377dc0..0x6377e3e`, 126B) is the same
template with the value replaced by the constant 1
(`movb $0x1,0x7(%rsp)`; no global load).

`thread/allocated` (`0x63749f0..0x6374bfa`, 522B) loads ctx+0x338
to the stack temp, then the u64 read contract: write attempt -> 1;
oldp/oldlenp absent -> 0; `*oldlenp` == 8 -> `*oldp` = value, 0;
else the compiler-unrolled bounded copy of min(`*oldlenp`, 8),
`*oldlenp` := copied count, 0x16.

`stats/allocated` (`0x637b190..0x637b440`, 688B) is the same u64
read contract, but the value is `*(*0x6712138)` loaded under the
init mutex `0x67121a0` with the standard record discipline
(trylock; contention -> wait helper `0x63bf680` on record base
`0x6712160`, contended byte `0x67121c8` := 1, retry; counters
`0x6712198`/`0x6712188`, last-ctx `0x6712190`; byte cleared and
mutex unlocked on every exit path, including write refusal).

Whole-`.text` E8/E9 census: 0 direct entries per leaf. `.rela.dyn`
slots (node+0x20 -> handler): `0x64dea80` -> `0x63737c0`,
`0x64de8a0` -> `0x63721c0`, `0x64deea8` -> `0x6377dc0`,
`0x64def48` -> `0x63749f0`, `0x64daac0` -> `0x637b190`.

### Bin init `0x63ec4c0..0x63ec5f4`

Record base rcx+0x28a8 (mutex rcx+0x28e8, contended byte
rcx+0x2910, counters rcx+0x28e0/rcx+0x28d0, last-ctx rcx+0x28d8).
`mov %rcx,0x28(%rsi)` stores the arena pointer to bin+0x28;
`movups` self-links bin+0/+8; the two insert-after-head splices
(head slots rcx+0x2898 and rcx+0x28a0, head preserved when
non-empty, set to the new node when empty); (rdx+8) to bin+0x20;
contended byte cleared; tail-jump to `pthread_mutex_unlock`.
Callers: 27 E8 + 1 E9 (tail-jump at `0x63ee02d`) across 19 caller
FDEs; the enable slow path FDE holds 4 E8 (0x63ed3fd, 0x63ed50c,
0x63ed5ad, 0x63ed63a).

### Bin get-or-create `0x634ebb0..0x634eccd`

Mutex `0x6511700`, record base `0x65116c0`, contended byte
`0x6511728`, counters `0x65116f8`/`0x65116e8`, last-ctx
`0x65116f0` — the standard record pattern (trylock; contention ->
wait helper `0x63bf680` on the record base, contended byte := 1,
retry). Index guard: ebx > 0xffe skips the table (result 0) but
still runs the tail. Otherwise: eax = [0x65096b0]; index == counter
-> `lock addl $0x1` on the counter; r12 = [0x65096c0 + index*8];
miss (0) -> create call `0x6364430` (rbp, ebx, r13) fills r12.
Unlock (contended byte cleared), then: index 0 returns r12
directly; else `0x6367450`(ebx) nonzero returns r12,
`0x6368e40`(rbp, ebx) zero returns r12, otherwise `0x63bf5b6`
log + `abort`. The table at `0x65096c0` is the same table the
teardown slots index (by pointee +0x13450), and the counter at
`0x65096b0` sits 8 bytes below it; the create callee
`0x6364430` sits 0x10 above the teardown release callee
`0x6364420` (adjacency noted, not claimed as a pair). Callers:
64 E8 + 4 E9, all 68 raw-scan sites capstone-verified in their
enclosing FDEs; the enable slow path FDE holds 3 E8 (0x63ed3e1,
0x63ed5e9, 0x63ed723).

### Interval consumer window `0x63c4316..0x63c43a3`

The window's instruction sequence: prof-byte branch
(`cmpb $0x0,0x6713606`; zero -> flag `0x67123a0` := 1, shared
success epilogue with ebp = 0); `0x6712438` := [0x64ffcf0];
call `0x63ce240` (nonzero -> fail); byte snapshots to
`0x67125d0`/`0x67124d0`/`0x6712550`; call `0x63ccd30` (nonzero ->
fail); `mov 0x6712440,%rsi; mov %rdi(=0),0x6712430`; call
`0x63c4bf0` with rdi = `0x67125e0` (nonzero -> fail). The FDE's
11 static `0x63bf840` sites and the remaining tail (allocs to
`0x6714500`/`0x67144f0`, calls `0x63d7bb0`/`0x63d7b90`, shared
success epilogue) are characterized from the full-FDE objdump,
not exhibited. Sole caller: E8 `0x634f44f` in FDE
`0x634f0b0..0x634f8d5`.

### Gate callees

`0x63c3b70`: `mov 0x68(%rdi),%rsi; test; je ret; jmp 0x63cf8c0`.
`0x63539d0` / `0x6353a20`: slot test (0x88 / 0x90), table
`0x65096c0` indexed by pointee +0x13450, call `0x6364420` with
flag 1 / 0, slot cleared. `0x63efd20`: endbr64 + ret (no-op).
Gate-FDE E8 sites: 0x63ef834, 0x63ef83c, 0x63ef844, 0x63ef858,
in that order — confirming packet #260's gate-body
characterization with no correction needed.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed by
this packet; the exhibits are evidence windows only, verified
against binary slices and regenerated objdump.

## Results and limitations

- Verifier: exit 0 (see README for the check list).
- Unit tests: 10/10 standalone, tamper controls run first.
- `make verify`: exit 0 (tally in the PR body); `make
  catalogue-check`: exit 2, pre-existing `Stale catalogue:
  README.md` on the new base, not a packet regression.
- Full `make test` not attempted (584 files; hours-long run,
  VM-restart risk); no full-suite tally claimed.
- Limits: 171 leaves remain; the consumer FDE beyond the window,
  the `0x63bf840` internals, and the remaining bin-setup callees
  are undecoded; global identities beyond their roles are
  undetermined from the file.

## Next question (#262)

Continue leaf classification with the next batch (`opt/prof_prefix`,
`opt/prof_active`, `opt/lg_prof_sample`, `thread/allocatedp`,
`thread/deallocated`); decode the remaining enable-slow-path
bin-setup callees (`0x63d9880` first; `0x63ec7a0`'s FDE overlaps a
lu-wait-callers window at `0x63ec890..0x63ec8a3`, so claim only
unclaimed bytes; `0x63d9700` is packet #215's handler and must not
be re-attempted); decode the consumer check helper `0x63bf840`.
