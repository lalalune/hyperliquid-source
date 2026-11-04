# RE-001-node115-lu-prof-thread-leaves-bin: lu prof/thread value leaves, bin removal, and the record initializer

- Component ID: RE-001 node-115 leaf classification (packet #262)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`
  (105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation for all exhibited bytes and counts; inference
  for value identities (stated as roles where the file cannot prove more);
  unresolved items listed at the end.
- Scope included and excluded: 5 control-tree leaves, 2 bin-setup callees
  (one split around a prior packet's claimed window), and the record
  initializer `0x63bf840`. Excluded: the remaining 166 leaves, the
  bin-removal cleanup callee `0x63ec690`, and the internals of callees
  named only by census.

## Reproduce

Worktree `~/workspace/hl-wt-calls262-115`, branch
`codex/re-004-calls262-115`, at the upstream main above. Static analysis
only; the binary was never executed.

- Leaf resolution: walk the control tree from root node `0x64da4c0`
  (children stride `0x28`, count at node `+0x10`, children at `+0x18`,
  name at `+0x08`, handler slot at `+0x20`), recovering relocated
  pointers from `.rela.dyn` RELATIVE addends. Validated against packet
  #261's known leaves before resolving the new batch.
- FDE bounds: `.eh_frame` parser (CIE augmentation zR, sdata4
  pcrel encoding `0x1b`); 135,313 FDEs parsed.
- Exhibits: raw bytes sliced at file offset VA − `0x1000` (`.text`);
  objdump text via `objdump -d --start-address --stop-address` with the
  path-embedding header lines stripped.
- Census: raw `.text` scan for E8/E9 rel32 targets; every reported site
  confirmed as an objdump call/jmp row in its enclosing FDE at build
  time. Leaf zero-counts are airtight under raw scan (a real E8/E9
  opcode byte is always present in the byte stream).
- Coordinate system: `.text` file offset = VA − `0x1000`;
  `.data.rel.ro` file offset = VA − `0x2000`; `.rodata` file offset =
  VA as-is; `.data` file offset = VA − `0x3000` (section
  `0x64efa20`/`0x64eca20`); `.bss` has no file bytes.

## Evidence

### Leaves (handlers reached only by dispatcher indirect tail-call)

| leaf | node | slot | handler FDE | class |
| --- | --- | --- | --- | --- |
| `opt/prof_prefix` | `0x64dea88` | `0x64deaa8` | `0x6373850..0x6373a5a` (522B) | read-only u64 |
| `opt/prof_active` | `0x64deab0` | `0x64dead0` | `0x6373a60..0x6373ae6` (134B) | read-only byte |
| `opt/lg_prof_sample` | `0x64deb00` | `0x64deb20` | `0x6373b80..0x6373d97` (535B) | read-only u64 |
| `thread/allocatedp` | `0x64def50` | `0x64def70` | `0x6374c00..0x6374e0a` (522B) | read-only u64 |
| `thread/deallocated` | `0x64def78` | `0x64def98` | `0x6374e10..0x637501a` (522B) | read-only u64 |

Each slot holds exactly one `.rela.dyn` RELATIVE entry whose addend
equals the handler address (verified by entry count, not just by
lookup). Each handler: 0 E8 / 0 E9 direct entries. Contract (all 5):
write attempt (newp or newlen nonzero) returns 1; oldp or oldlenp
absent returns 0; exact-length read returns 0; short read copies
min(`*oldlenp`, size) from a stack temp, sets `*oldlenp` to the copied
count, returns `0x16`.

- `opt/prof_prefix`: fast path stores the lea result `0x6712600`
  itself to `*oldp` — the returned u64 is the buffer address, not a
  loaded pointer. The buffer is in `.bss`; its runtime contents are
  not in the file.
- `opt/prof_active`: value byte at `0x64ffcf9` (`.data`,
  file-initial 1). Same byte packet #261's consumer snapshots into
  prof-state `0x67125d0`.
- `opt/lg_prof_sample`: value qword at `0x64ffcf0` (`.data`,
  file-initial `0x13` = 19). Same global packet #261's consumer copies
  into `0x6712438`.
- `thread/allocatedp`: `add $0x338,%rdi` — returns the address
  ctx+0x338 itself. Contrast packet #261's `thread/allocated`, which
  loads the value AT ctx+0x338 (`mov 0x338(%rdi),%rdx`).
- `thread/deallocated`: `mov 0x348(%rdi),%rdx` — value at ctx+0x348.

### Bin table init `0x63d9880..0x63d9a64` (484B, 50 strict)

No calls, no branches: 48 `movq` stores writing 1 to every even qword
and 0 to every odd qword of the region at rdi (`0x00..0x178`, 24 pairs
of (1, 0)), then `ret`. Census: 108 E8, 0 E9; enable slow path holds
`0x63ed478` and `0x63ed4e7` (matching packet #260's x2). The FDE
starts at the next FDE after packet #215's handler FDE
(`0x63d9700..0x63d987b`).

### Bin removal `0x63ec7a0..0x63ec900` (352B FDE, split exhibits)

Record discipline shared with packet #261's bin insert: record base =
arena pointer + `0x28a8`; mutex base+`0x40`, contended byte
base+`0x68`, every-entry counter base+`0x38`, change counter
base+`0x28`, last-ctx base+`0x30`. In this function rbp =
[rsi+`0x28`] (the arena pointer), so the concrete slots are mutex
rbp+`0x28e8`, contended byte rbp+`0x2910`, counters rbp+`0x28e0` /
rbp+`0x28d0`, last-ctx rbp+`0x28d8`, list heads rbp+`0x2898` /
rbp+`0x28a0`.

- Head (`0x63ec7a0..0x63ec890`): trylock; contention jumps to
  `0x63ec890`. Counters as above. First-list unlink (0/+8 links)
  with head path at `0x63ec8d0`; second-list unlink (0x10/0x18 links)
  with head path at `0x63ec8b0`. Cleanup call `0x63ec690` (ctx,
  arena record, bin+`0xa8`), contended byte := 0, unlock,
  bin+`0x28` := 0, return.
- Middle (`0x63ec890..0x63ec8a3`, NOT exhibited): packet #252's
  `r28_wait` exhibit — lea record, call wait helper `0x63bf680`,
  contended byte := 1; the tail at `0x63ec8a3` jumps back to retry.
- Tail (`0x63ec8a3..0x63ec900`): the retry jump, the second-list
  head path, and the first-list head path.
- Callers: 4 E8, 0 E9 (`0x63ec975`, `0x63ed59c`, `0x63ed629`,
  `0x63edcbf`).

### Record initializer `0x63bf840..0x63bf8fc` (188B, 51 strict)

- `movups` zeroes rdi+`0x00..+0x3f` (after rdi += 8, stores at
  −8/+8/+0x18/+0x28 relative to the bumped rdi).
- Two calls to single-qword copy helper `0x63bfbf0` (`mov
  (%rsi),%rax; mov %rax,(%rdi); ret`) copy the template qword (0)
  from `.rodata` `0xb9e830` to rdi+`0x08` and rdi+`0x00` — redundant
  with the zeroing.
- `movq $0` to rdi+`0x30` (also redundant).
- Stack mutexattr: init, settype 0 (NORMAL), `pthread_mutex_init`
  at rdi+`0x40`, destroy attr. Returns 0 on success, 1 on
  mutexattr_init / mutex_init failure (stack-check failure aside).
- Reads only rdi. At its 11 consumer call sites the rsi/rdx/rcx
  setup (string, size, 0) is dead: rsi is overwritten with
  `0xb9e830` before use; rdx/rcx are never read.
- Consumer sites (FDE `0x63c41c0..0x63c44d9`): 9 entry-chain sites
  initializing individual records (`0x6712560`, `0x6712460`,
  `0x67124e0`, `0x6714620`, `0x67145a0`, `0x67123c0`, `0x6717620`,
  `0x67276e0`, `0x6714520`) and 2 loop sites initializing arrays
  element-wise with a `0x70` stride (over `0x1c000` bytes at the
  allocation stored to `0x6714500`, site `0x63c441b`; over `0x7000`
  bytes at the allocation stored to `0x67144f0`, site `0x63c4478`).
- Whole-binary census: 35 E8 + 2 E9 (E9 at `0x63b6ed9` and
  `0x63d96f9`).

## Implementation and comparison

Not implemented: this packet is evidence only, no Rust reconstruction
is claimed. No gate beyond the verifier, unit tests, `make verify`,
and the honestly reported `make catalogue-check` result is requested.

## Results and limitations

- Exhibits: 9 windows, 3240 bytes, 801 strict mnemonic lines
  (address + bytes field + tab + mnemonic starting with a lowercase
  letter; byte-continuation lines excluded).
- Leaf arithmetic: 33 + 5 + 166 = 204. Remaining unclassified: 166.
- Disjointness: range-only collector (all prior record shapes:
  string `range`, `[start, end]` lists, `start`/`end` pairs in
  `exhibits`/`windows` lists or dicts; census/cited-only subtrees and
  enclosing-`fde` annotations excluded), deduplicated by real packet
  slug, over the merged tree plus packets #183–#261 worktrees. No
  overlap with packets #183–#261 or packet #232's FDE
  `0x63b8820..0x63b8d85`.
- Not determined from the file: runtime contents of `.bss` buffer
  `0x6712600`; runtime values of `.data` bytes `0x64ffcf9` /
  `0x64ffcf0` (only file-initial values reported); the subsystem
  meaning of the 24 (1, 0) pairs; the internals of `0x63ec690` and
  the remaining bin-setup callees named only by census.
- Next question (#263): continue leaf classification (166 remain);
  decode bin-removal cleanup callee `0x63ec690`; decode the remaining
  enable-slow-path bin-setup callees (`0x6352fc0`, `0x6352f60`,
  `0x63e91c0`, `0x6365150`); survey the 108 bin_table_init callers'
  contexts.
