# RE-001: lu bin_table_init caller, 6 sites (dump routine)

Node-115-only light packet: the fourth bin_table_init caller FDE
0x63d4bbe..0x63d5428 (2154 bytes, 454 strict lines, 69 calls,
1 ret), the first next-question option of packet #277. Unlike
packets #275/#276/#277, this caller is not a lookup-walk
function: it is a dump routine that creates a file, emits
records through helper 0x63d481a, and initializes a bin table
at six rbp == 0 branches across three list-walk phases. The
opt children array is exhausted at group 64 (#274), so this
packet classifies no leaf; the 107 static leaves remaining at
packet start are unchanged.

## Pointer correction (not a re-claim)

Packet #277's records named this FDE "0x63d4bbe..0x63d5428"
with 2410 bytes. The range and the 6 raw candidates are
confirmed, but the byte count is wrong: 0x63d5428 - 0x63d4bbe
= 0x86a = 2154 bytes, computed by program from the
`.eh_frame` bounds. The 2410 figure does not match any
`.eh_frame` boundary for this FDE. No classified leaf or
prior framing is otherwise corrected.

## The FDE (1 window, 2154 bytes, 454 strict lines, 69 calls, 1 ret)

FDE bounds come from `.eh_frame` (PC-relative sdata4 encoding,
fixed 4-byte range fields — not ULEB, per packet #270's lesson),
not from endbr64 scanning. The FDE opens with six pushes, a
0xa18-byte frame, and a stack canary at 0xa08(%rsp). There is
exactly one `ret` (0x63d5427), reached through a single canary
check; the only out-of-FDE transfer on canary mismatch is the
`__stack_chk_fail` call at 0x63d5411. The previous FDE ends
exactly at this FDE's start (gap 0) and the next FDE starts
exactly at this FDE's end (padding 0).

Entry contract (from register use, not from symbols — the
binary's symbol names are stripped to a single base label):
rdi is saved to rbp at entry and used as a context argument
throughout; the key material is carried in caller registers
and stack slots, not in a single key-descriptor struct.

## Entry gates and file creation

Two `.bss` gate bytes must both be nonzero (0x6713606 and
0x67123a0); if either is zero, the function returns 1 early.
It then calls helper 0x63d46b4 and consults state word
0x67157f4: if it equals 1, the mutex 0x67146e0 is unlocked,
flag byte 0x6714708 is cleared to 0, and the function returns
1. Otherwise the state is set to 2, the mutex is unlocked,
and the flag is cleared.

If state byte 0x67157f0 is zero, the function creates a file
with creat() (path pointer from `.bss` 0x67147e0, mode 0x1a4
= 0644) and stores the descriptor in the 0x4(%rsp) slot. On
failure (descriptor -1), it reads errno, calls error-report
helper 0x63bf5b6, and then aborts if `.bss` byte 0x651174d
is nonzero, otherwise returns 1. If 0x67157f0 is nonzero, the
descriptor slot is set to 0 and no file is created.

## Setup and three list-walk phases

Setup helper 0x636c4a0 is called with (rdi = rbp, rsi = lea
0xc0(%rsp), rcx = lea 0x48(%rsp) whose first slot holds the
fd, rdx = 0x63d3b90, r8 = 0, r9 = 0x10000). An output struct
at 0xa0(%rsp) is initialized (0xa0 = 1, 0xa8 = r8 with r8 =
lea 0x636c530, 0xb0 = r12, 0xbc = 0) and passed (as rbx) to
the phase helpers.

The emit helper 0x63d481a (14 sites) takes (rdi = output
struct, rsi = `.rodata` format string, rdx = length, rcx =
value pointer); its internals are not decoded here (context,
not claims).

Each of the three phases walks a `.bss` list head until null,
emits records, and ends with the same tail shape: a
0x63d3f0e call, a 0x6727a00-table lookup, a bin_table_init
site pair (rbp == 0 branches), a 0x63d4048 call, a `lock sub`
refcount decrement on a 0x65096c0-table entry indexed by
(leaf & 0xfff), and a 0x63d4171 call, then loops.

| phase | list head | loop head | bin_table_init sites |
| ----- | --------- | --------- | -------------------- |
| 1 | 0x6714728 | 0x63d4e7d | 0x63d4eed, 0x63d4f2b |
| 2 | 0x6714738 | 0x63d4fd3 | 0x63d50af, 0x63d50e7 |
| 3 | 0x6714718 | 0x63d517f | 0x63d5267, 0x63d529c |

Phase 2 additionally contains an inner entry loop (count at
node +0x18, array at node +0x10, 8-byte stride, helper
0x63bf47c with length 0x13). Phase 3 emits seven records
(lengths 6, 6, 6, 6, 5, 5, 5) over node fields +0x8..+0x38.
Phase 1 reads the prof_time_resolution index slot (`.bss`
0x6712370) and its table (`.data` 0x64ffca0) — the same slots
packet #274 classified — but does not re-claim them.

## bin_table_init: 6 sites, three arg shapes, all rbp == 0 branches

Every site is reached from a `test %rbp,%rbp` followed by
`jne` past the site block — bin_table_init initializes a
fresh bin table whenever the walk finds no context (rbp ==
0). Unlike packets #275 (one stack temp) and #276 (one
register), this FDE uses three argument shapes. bin_table_init
itself (0x63d9880..0x63d9a64) was claimed by packet #262
(PR #2810); only its caller FDE is claimed here.

| site | rejoin | argument |
| ---- | ------ | -------- |
| 0x63d4eed | 0x63d4ef2 | rdi = r13 |
| 0x63d4f2b | 0x63d4f30 | rdi = lea 0x870(%rsp) |
| 0x63d50af | 0x63d50b4 | rdi = lea 0x3f0(%rsp) |
| 0x63d50e7 | 0x63d50ec | rdi = lea 0x570(%rsp) |
| 0x63d5267 | 0x63d526c | rdi = r13 |
| 0x63d529c | 0x63d52a1 | rdi = mov 0x8(%rsp),%rdi |

## What this FDE does NOT contain

Unlike packets #275/#276/#277, this FDE contains no lu-miss
handler calls (0 sites to 0x63d9700, verified by census) and
no radix-walk skeleton (no (key >> 0x1a) & 0xf0 top-index
walk, no bsr size-class block). The 0x65096c0 and 0x6727a00
tables appear only for refcount decrements and value
lookups in the phase tails, not for a walk. The lu-miss
handler (packet #215's FDE) is cited, not claimed.

## Epilogue

After the phases, helper 0x63d3dfe runs, then 0x636c620
(rdi = rbp, rsi = lea 0xc0(%rsp)). If `.bss` byte 0x67147b0
is nonzero, helper 0x63d3080 is called twice (0x6714780,
0x6714740). Eight `.bss` list heads are zeroed (0x67147c0,
0x67147b8, 0x6714738, 0x6714730, 0x6714728, 0x6714720,
0x6714718, 0x6714710), helper 0x63d46b4 is called again,
state 0x67157f4 is reset to 0, the mutex 0x67146e0 is
unlocked, and flag 0x6714708 is cleared. If 0x67157f0 is
zero, the descriptor is closed. The return value is 1 if
close fails, else 1 if the 0x50(%rsp) slot equals -1, else
0; the 0x50(%rsp) slot is not written anywhere in this FDE,
so its value comes from the caller.

## Other callees (context only, not claims)

- 0x63d481a (14 sites): emit helper, described above.
- 0x63d3dfe (4 sites), 0x63d3bd3 / 0x63d3d66 / 0x63d3d89 /
  0x63d3dc8 / 0x63d3f0e / 0x63d4048 / 0x63d4171 (3 sites
  each): phase helpers, internals not decoded.
- 0x63f0b70 (3 sites): pthread_mutex_unlock@plt.
- 0x63d46b4 (2 sites): entry/epilogue helper.
- 0x63bfb90 (2 sites), 0x63d3ce2 (2 sites), 0x63d3080
  (2 sites): phase/epilogue helpers.
- Single sites: creat@plt (0x63f1b70), __errno_location@plt
  (0x63f0ad0), error-report helper (0x63bf5b6), abort@plt
  (0x63f0bf0), setup helper (0x636c4a0), 0x63d3d27,
  0x63bfd50, 0x63d7c40, 0x63bf47c, 0x63d46fb, epilogue
  helper (0x636c620), close@plt (0x63f0ab0),
  `__stack_chk_fail`@plt (0x63f0d70).

## Exhibits (1 window, 2154 bytes, 454 strict lines)

Strict = address + bytes field + tab + mnemonic starting with a
lowercase letter; objdump byte-continuation lines excluded.
`.hex` exhibits contain raw binary bytes, not hex text.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| bintableinit_caller_dump_6sites | 0x63d4bbe..0x63d5428 | 2154 | 454 |

Padding to the next FDE: the next FDE starts at 0x63d5428
(verified from `.eh_frame`), so the padding is 0 bytes.
The previous FDE ends exactly at 0x63d4bbe (the FDE at
0x63d4ad8..0x63d4bbe), so the gap before this FDE is 0.

## Verification

- Static verifier `tools/node115_lu_bintableinit_caller_dump_6sites.py`
  (byte reads only; never executes the binary): exit 0.
- Own unit tests `tests/test_node115_lu_bintableinit_caller_dump_6sites.py`:
  standalone, 9/9 pass, including regeneration comparison,
  independent strict recount, independent call census, and
  tamper controls run first (hex flip, strict-count change,
  call-site list change, injected overlap — each confirmed
  to fail the verifier, and a clean temp copy confirmed to
  pass).
- `make verify`: exit 0 (559 evidence-packet manifests, 7161
  entries — actual tally: base 7154 + this packet's 7 MANIFEST
  entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue:
  README.md` on the new base (verified: no catalogue file is
  touched by this packet; only the packet dir, tools file, and
  tests file are added) — not a packet regression, and not
  claimed as passing.
- Full `make test` is NOT attempted: 584 test files on the new
  base take hours and risk a VM-restart kill mid-run; no
  full-suite tally is claimed.
- MANIFEST.sha256 verified with `sha256sum -c` (all 7 entries
  OK).

## Disjointness

The verifier's collector scans the merged tree plus prior
worktree records (#183–#277), deduplicated by real packet slug,
and gathers ONLY exhibited windows: string range fields,
[start, end] lists (hex strings or int pairs), and start/end
pairs inside exhibits/windows lists or dicts or a dict
literally named "window". It never collects enclosing-fde
annotation fields (packet #259 lesson), census/cited-only
metadata subtrees (packet #253 lesson), next-caller pointers,
or scan descriptors (direct_reference_scan, text_scan —
whole-section scan parameters, not claimed windows) or
control-flow edges (cfg_edges — from→to jumps, not
windows). The window is disjoint
from every prior claimed range, from packet #232's merged FDE
`0x63b8820..0x63b8d85` (checked explicitly), from packet
#252's r28_wait window `0x63ec890..0x63ec8a3`, from packet
#215's handler FDE `0x63d9700..0x63d987b`, from packet
#261's group-36 tcache window `0x63721c0..0x6372246`, from
packet #261's opt_prof window `0x63737c0..0x6373846`, from
packet #262's prof_prefix, prof_active, and lg_prof_sample
windows, from packet #262's bin_table_init window
`0x63d9880..0x63d9a64`, from packet #269's xmalloc window
`0x6378090..0x637809a`, from packet #261's
`0x634ebb0..0x634eccd` window, from packet #275's caller FDE
`0x63cba10..0x63ccd22`, from packet #276's caller FDE
`0x63c9c80..0x63cb146`, and from packet #277's caller FDE
`0x63ce8c0..0x63cf8bc`. The slug
`RE-001-node115-lu-bintableinit-caller-6sites-dump` does not
collide with any merged-tree directory.

## Not covered (explicit)

- The remaining 107 static leaves, unchanged by this packet.
- The callee FDEs' internals beyond their call-site argument
  patterns (see above).
- Runtime values of the `.bss` addresses (gate bytes,
  state words, mutex, list heads, path pointer, tables) —
  only the mechanism is reported.
- Whether the dumped records belong to one named structure:
  observed emit pattern only, not proven.
- The next bin_table_init caller FDE 0x63bd8c0..0x63be4ce
  (5 raw candidates): not decoded.
- Packet #277's framings are NOT corrected or re-claimed
  here, except for its next_caller byte count (2410),
  which this packet corrects to 2154 as described above;
  nothing in this packet's disassembly contradicts #277's
  classified caller FDE.
