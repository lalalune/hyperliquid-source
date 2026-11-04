# RE-001-node115-lu-prof-thread-leaves-bin: lu prof/thread value leaves, bin removal, and the record initializer

Packet #262 in the RE-001 node-115 leaf-classification chain, answering
packet #261's next question. It classifies 5 more control-tree leaves
(all read-only), decodes the remaining assigned bin-setup callees
(`0x63d9880` and the split `0x63ec7a0` window), and decodes the
consumer helper `0x63bf840` — refining packet #261's "check helper"
framing into a record/mutex initializer.

Target: node #115, `artifacts/node/115/hl-node` (105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`),
upstream main `05bc2de303c05525b71e7e257426e741bc66a390`. Static
analysis only; the binary was never executed. `.hex` exhibit files
contain raw binary bytes, not hex text.

## Leaf resolution method

Leaves were resolved by walking the control tree from root node
`0x64da4c0` (13 children): each node carries a flag at `+0x00`, a name
pointer at `+0x08`, a child count at `+0x10`, a children pointer at
`+0x18`, and a handler slot at `+0x20`; children stride `0x28`.
Relocated pointers are zero in the file and were recovered from
`.rela.dyn` RELATIVE addends (the method packet #256 established for
`.rela.dyn` recovery). The walker was validated against packet #261's
known leaves (`opt/prof` -> `0x63737c0`, `thread/allocated` ->
`0x63749f0`, `stats/allocated` -> `0x637b190`) before resolving the
new batch.

## Leaves classified here (5, all read-only)

All 5 handlers are reached only by dispatcher indirect tail-call: a
whole-`.text` E8/E9 census gives 0 direct entries per leaf, and each
leaf's `.rela.dyn` slot (node + 0x20) holds exactly one RELATIVE
addend equal to the handler address. Write attempt (newp or newlen
nonzero) returns 1 in every leaf; oldp or oldlenp absent returns 0;
exact-length read returns 0; short read copies min(`*oldlenp`, size)
from a stack temp, sets `*oldlenp` to the copied count, returns 0x16.

- `opt/prof_prefix` (node `0x64dea88`, FDE `0x6373850..0x6373a5a`,
  522B): read-only u64. Value is the address `0x6712600` itself (the
  prof-prefix string buffer in `.bss`, whose runtime contents are not
  in the file). `*oldlenp` == 8 gives `*oldp` = `0x6712600`, 0.
- `opt/prof_active` (node `0x64deab0`, FDE `0x6373a60..0x6373ae6`,
  134B): read-only byte. Value is the byte at global `0x64ffcf9`
  (file-initial 1; the runtime value may differ). This is the same
  byte packet #261's consumer snapshots into prof-state `0x67125d0`.
  `*oldlenp` == 1 gives `*oldp` = byte, 0.
- `opt/lg_prof_sample` (node `0x64deb00`, FDE `0x6373b80..0x6373d97`,
  535B): read-only u64. Value is the qword at global `0x64ffcf0`
  (file-initial `0x13` = 19). This is the same global packet #261's
  consumer copies into `0x6712438`. `*oldlenp` == 8 gives `*oldp` =
  value, 0.
- `thread/allocatedp` (node `0x64def50`, FDE `0x6374c00..0x6374e0a`,
  522B): read-only u64. Value is the address ctx+0x338 itself — the
  pointer variant of packet #261's `thread/allocated`, which loads
  the value AT ctx+0x338. `*oldlenp` == 8 gives `*oldp` = ctx+0x338, 0.
- `thread/deallocated` (node `0x64def78`, FDE `0x6374e10..0x637501a`,
  522B): read-only u64. Value is the qword at ctx+0x348.
  `*oldlenp` == 8 gives `*oldp` = value, 0.

Previously classified: 33 (packets #257/#258/#259/#260/#261).
Classified here: 5. Remaining unclassified: 166 of 204 leaves. This
packet does not claim exhaustive coverage.

## Bin table init: `0x63d9880..0x63d9a64` (full FDE, 484B, 50 strict)

A pure initializer with no calls and no branches: it stores 1 to every
even qword and 0 to every odd qword of the 0x180-byte region at rdi
(24 pairs of (1, 0) at offsets `0x00..0x178`), then returns. Callers:
108 E8, 0 E9, including 2 E8 in the enable slow path FDE
(`0x63ed478`, `0x63ed4e7`), matching packet #260's census. The FDE
starts at the next FDE after packet #215's handler FDE
(`0x63d9700..0x63d987b`); `0x63d9700` itself is not re-attempted.

## Bin removal: `0x63ec7a0..0x63ec900` (split windows, 240B + 93B)

The removal twin of packet #261's bin insert (`0x63ec4c0`), sharing
its record discipline (record base = arena pointer + `0x28a8`: mutex
at base+`0x40`, contended byte at base+`0x68`, every-entry counter at
base+`0x38`, change counter at base+`0x28`, last-ctx at base+`0x30`).
Args: rdi = ctx, rsi = bin; rbp = [rsi+`0x28`] (the arena pointer
bin_init stores to bin+`0x28`).

- Trylocks the record mutex; contention jumps to the wait path at
  `0x63ec890`, which is packet #252's exhibited `r28_wait` window
  (`0x63ec890..0x63ec8a3`, cited only, not exhibited here): lea
  record, call wait helper `0x63bf680`, contended byte := 1, then the
  tail at `0x63ec8a3` jumps back to retry.
- On success: every-entry counter +1; on ctx change, change counter
  +1 and last-ctx := ctx.
- Unlinks bin from the first doubly-linked list (0/+8 links), with a
  head-replacement path when bin is the head (`0x63ec8d0`); then
  unlinks bin+`0x10` from the second list (0x10/0x18 links), with its
  own head path (`0x63ec8b0`).
- Calls cleanup `0x63ec690` (ctx, arena record, bin+`0xa8`; named
  only, not decoded), clears the contended byte, unlocks, clears
  bin+`0x28` (the arena pointer), and returns.
- Callers: 4 E8, 0 E9 — `0x63ec975` (FDE `0x63ec900..0x63ed06d`),
  `0x63ed59c` and `0x63ed629` (enable slow path FDE, matching packet
  #260's x2), `0x63edcbf` (FDE `0x63ed8b0..0x63edf05`).

The two exhibits adjoin packet #252's window without overlapping it:
head `0x63ec7a0..0x63ec890` (240B, 62 strict) and tail
`0x63ec8a3..0x63ec900` (93B, 17 strict).

## Record initializer: `0x63bf840..0x63bf8fc` (full FDE, 188B, 51 strict)

Refinement of packet #261 (which left this helper undecoded and
described only its call pattern): `0x63bf840` is a record/mutex
initializer, not a checker. It zeroes the 64-byte record header at
rdi (`+0x00..+0x3f` via `movups`), copies the template qword (0) from
`.rodata` `0xb9e830` to rdi+`0x00` and rdi+`0x08` via the single-qword
copy helper `0x63bfbf0` (redundant with the zeroing — the same
duplicate-store shape packet #254 noted for `0x63bfbf0`), zeroes
rdi+`0x30`, then initializes a PTHREAD_MUTEX_NORMAL mutex at
rdi+`0x40` via a stack mutexattr (init, settype 0, init, destroy).
It returns 0 on success and 1 if mutexattr_init or mutex_init fails
(stack-check failure aside).

The callee reads only rdi: the rsi/rdx/rcx arguments set at its call
sites are dead — rsi is overwritten with the fixed template address
`0xb9e830` and rdx/rcx are never read. So packet #261's consumer
entry chain initializes mutex records and aborts with return 1 on
init failure, rather than performing checks: 9 entry-chain sites
initialize individual records (at `0x6712560`, `0x6712460`,
`0x67124e0`, `0x6714620`, `0x67145a0`, `0x67123c0`, `0x6717620`,
`0x67276e0`, `0x6714520`), and 2 loop sites initialize arrays
element-wise with a `0x70` stride — over `0x1c000` bytes at the
allocation stored to `0x6714500` (site `0x63c441b`) and over `0x7000`
bytes at the allocation stored to `0x67144f0` (site `0x63c4478`).
Packet #261's 11-site count and its 9+2 characterization stand
(confirmed here: exactly 11 E8 in the consumer FDE); only the
"check" framing is refined.
Whole-binary census: 35 E8 + 2 E9 (E9 tail-jumps at `0x63b6ed9` and
`0x63d96f9`).

## Exhibits (9 windows, 3240 bytes, 801 strict lines)

Strict = address + bytes field + tab + mnemonic starting with a
lowercase letter; objdump byte-continuation lines excluded. 9 windows
(not 8-16) because each backs a different mechanism: 5 leaf windows, 1
bin-init window, 2 bin-removal windows split around packet #252's
claimed window, 1 record-init window.

| exhibit | range | bytes | strict |
| --- | --- | --- | --- |
| prof_prefix | `0x6373850..0x6373a5a` | 522 | 146 |
| prof_active | `0x6373a60..0x6373ae6` | 134 | 36 |
| lg_prof_sample | `0x6373b80..0x6373d97` | 535 | 147 |
| allocatedp | `0x6374c00..0x6374e0a` | 522 | 146 |
| deallocated | `0x6374e10..0x637501a` | 522 | 146 |
| bin_table_init | `0x63d9880..0x63d9a64` | 484 | 50 |
| bin_remove_head | `0x63ec7a0..0x63ec890` | 240 | 62 |
| bin_remove_tail | `0x63ec8a3..0x63ec900` | 93 | 17 |
| record_init | `0x63bf840..0x63bf8fc` | 188 | 51 |

## Verification

- `tools/node115_prof_thread_leaves_bin.py` exit 0 (byte reads only;
  binary identity, exhibit bytes, strict counts, objdump regeneration
  with the path-embedding header lines stripped, `.rela.dyn` slots,
  named E8/E9 sites by exact byte arithmetic, raw-scan census totals,
  disjointness, MANIFEST hashes).
- `tests/test_node115_prof_thread_leaves_bin.py` 10/10 standalone,
  including tamper controls run first: corrupting one exhibit byte,
  changing a strict count, and injecting an overlap each fail the
  verifier.
- `make verify` exit 0; `make catalogue-check` exit 2 with the
  pre-existing `Stale catalogue: README.md` failure on the new base,
  not a packet regression.
- Full `make test` is not attempted: the new base carries 584 test
  files, a full run takes hours and risks a VM restart mid-run. The
  gates above are the verified final state; no placeholder language
  is used.
- Disjointness: range-only collector over the merged tree plus
  packets #183-#261 worktrees, deduplicated by real packet slug,
  census/cited-only subtrees excluded. The collector gathers ONLY
  exhibited windows — string `range` fields, `[start, end]` lists,
  `start`/`end` pairs inside `exhibits` lists or dicts, and `windows`
  lists or dicts — never enclosing-`fde` annotation fields. No
  overlap with packets #183-#261 or with packet #232's FDE
  `0x63b8820..0x63b8d85`. Directory
  `RE-001-node115-lu-prof-thread-leaves-bin` does not collide with
  any merged-tree directory.

## Not covered (explicit)

- The remaining 166 leaves.
- Bin-removal cleanup callee `0x63ec690` (named only).
- The 108 bin_table_init callers' contexts beyond the enable-slow
  pair, and what the 24 (1, 0) pairs represent per subsystem.
- Enable-slow-path bin-setup callees beyond the two decoded here
  (`0x6352fc0`, `0x6352f60`, `0x63e91c0`, `0x6365150`, named only by
  packet #260's census; `0x63d9700` is packet #215's handler and must
  not be re-attempted).
- Runtime contents of `.bss` buffer `0x6712600` and runtime values of
  `.data` bytes `0x64ffcf9` / `0x64ffcf0` (only file-initial values
  are reported).

## Next question (#263)

Continue leaf classification (166 remain); decode bin-removal cleanup
callee `0x63ec690`; decode the remaining enable-slow-path bin-setup
callees (`0x6352fc0`, `0x6352f60`, `0x63e91c0`, `0x6365150`, named only
by packet #260's census); survey the 108 bin_table_init callers'
contexts.
