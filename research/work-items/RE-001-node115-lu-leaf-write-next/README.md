# RE-001-node115-lu-leaf-write-next: lu leaf write classification and the prof-byte writers

Packet #259 in the RE-001 node-115 leaf-classification chain. Packet #258
invited this continuation: classify the remaining control-tree leaves,
starting with `experimental/arenas_create_ext`, `thread/tcache/enabled`,
`thread/prof/name`, the `experimental/hooks` siblings, `prof.active`,
`prof.gdump`, and `prof.interval`; decode the TLS helper `0x63ef640`
(modes 0/3/5) and `0x63eec10`/`0x63ed870`; and decode the option-parser
FDE `0x6349be0..0x634eb7c` for the option names that set vs clear the
prof byte `0x6713606`.

## What was classified

9 leaves, all reached only by dispatcher tail-call (E8 0, E9 0 per leaf,
whole-`.text` census):

| leaf | class | headline |
| --- | --- | --- |
| `experimental/arenas_create_ext` | write | init-mutex + counters + 16B template swap + arena create |
| `thread/tcache/enabled` | read/write | 1-byte ctx value, slow paths `0x63ed090`/`0x63ed070` |
| `thread/prof/name` | read/write | prof-byte gate 2; 8-byte name pointer via `0x63c3c90`/`0x63c3d50` |
| `experimental/hooks/prof_backtrace` | read/write | prof-byte gate 2; get `0x63c40f0`, set `0x63c40e0` |
| `experimental/hooks/prof_dump` | read/write | prof-byte gate 2; get `0x63c4110`, set `0x63c4100` |
| `experimental/hooks/safety_check_abort` | write (pure action) | installs `0x63d9a70` argument; no read path |
| `prof/active` | read/write | prof-byte gate 2; set `0x63c3c10`, read `0x63c3b90` |
| `prof/gdump` | read/write | prof-byte gate 2; set `0x63c4060`, read `0x63c3fe0` |
| `prof/interval` | **read-only** | newp\|newlen nonzero returns 1; value is global `0x6712440` |

8 write/read-write leaves + 1 read-only leaf = 9 classified here.
Previously classified: 14 (packets #257/#258, cited not claimed).
**Remaining unclassified: 181 of 204 leaves.** This packet does not claim
exhaustive coverage; the 181 are listed as unclassified in records.json
only by count, and stay open for later packets.

## TLS helper `0x63ef640` (mode = 2nd argument)

State byte ctx+0x330. State > 2: store mode, then call `0x63ef410` if
mode <= 2 else call `0x63eec10`, and tail-call `0x63eec10`. State <= 2 and
mode > 2: the global-mutex path (mutex `0x67288e0`, counters, list splice,
contended-byte clear, unlock), store mode, tail-call `0x63eec10`.
State <= 2 and mode <= 2: spin/wait loop; exits to the xchg path when
state > 2, gate neighbour `0x64ffab0` != 0, ctx+0 != 0, or ctx+1 > 0.
Callers (whole-`.text` E8 census): 5, none E9 — 3 in the TLS slow path
FDE `0x63ef8e0..0x63efba2` (modes 5/3/0 per packet #258), 1 in FDE
`0x63ef810..0x63ef8d7`, 1 in FDE `0x6367e60..0x6368e3f`.

`0x63eec10` (97B, "cached bounds refresh"): if state == 0, clamp
ctx+0x10/+0x20 to 0 when >= -4095 and store to ctx+0x340/+0x350, then a
`lock orq $0,(%rsp)` barrier and a state re-check; if state != 0 on
entry or after the barrier, zero 0x340/0x350 and return. Callers: E8 4
(1 in `0x63ef640`, 3 in the slow path), E9 5 (1 in `0x63ef5e0`, 3 in
`0x63ef640`, 1 in FDE `0x63efc30..0x63efcbc`).

`0x63ed870` (52B, "apply global tcache-enabled default"): store global
byte `0x64ffdf8` to ctx+0, call `0x63ef5e0`, and if the global is still
nonzero call enable slow path `0x63ed090`. Single caller: E8
`0x63efb88` in the TLS slow path.

## Option parser: the prof byte writers

FDE `0x6349be0..0x634eb7c`. Option `"prof"` + value `"true"` sets
`0x6713606` to 1 (store cited from packet #258, not claimed here);
`"prof"` + `"false"` clears it to 0 (also cited, not claimed). Option
`"prof_leak_error"` + `"true"` sets neighbour byte `0x6713602` to 1
(exhibited); + `"false"` clears `0x6713602` to 0 (exhibited). When the
init-done flag `0x651174b` is nonzero, both cases log via
`<jemalloc>: -- Set conf value: %.*s:%.*s\n` — indirect evidence this
parser is the jemalloc mallctl option path. Packet #258's latch
`0x63c4140..0x63c41b1` also sets the prof byte (cited, not claimed).

## Exhibits

17 windows, 2283 bytes, 582 strict mnemonic lines. `.hex` files contain
raw binary bytes (packet #255 format), not hex text; the verifier,
tests, and MANIFEST all treat them as raw. 17 windows (not 8-16) because
each window backs a different mechanism: 9 leaf windows, 3 TLS windows
(core + `0x63eec10` + `0x63ed870`), and 5 option-parser windows.
Full-FDE exhibits: `tcache_enabled`, `hooks_safety`, `prof_active`,
`prof_gdump`, `fn_eec10`, `fn_ed870`. Head exhibits (tails characterized,
not exhibited): `arenas_create_head`, `prof_name_core`,
`hooks_backtrace_head`, `hooks_profdump_head`, `prof_interval_head`,
`tls_helper_core`, and the 5 option-parser windows.

## Verification

- `tools/node115_leaf_write_next.py` exit 0 (byte reads only).
- `tests/test_node115_leaf_write_next.py` 10/10 standalone, including a
  tamper control run first: corrupting one exhibit byte fails the
  verifier (packet #257 lesson).
- `make verify` exit 0 (559 evidence-packet manifests, 7193 entries:
  base 7154 + this packet's 39); `make catalogue-check` exit 2 with
  the pre-existing `Stale catalogue: README.md` failure on the new
  base, not a packet regression. Full `make test` is not attempted:
  584 test files on the new base take hours and risk a VM restart
  mid-run.
- Disjointness: recursive range+fde collector over the merged tree plus
  packets #255-#258 worktrees, deduplicated by real packet slug, with
  census/cited-only subtrees excluded (packet #253/#254 method). No
  overlap with packets #183-#258 or with packet #232's FDE
  `0x63b8820..0x63b8d85`. Claimed ranges adjoin but do not overlap
  packet #258's prof-byte stores (`0x634c035..0x634c047`,
  `0x634d08c..0x634d09d`).

## Not covered (explicit)

- The remaining 181 leaves (read/write classification still open).
- `0x63ef5e0` and `0x63ef410` internals (called, not decoded).
- The writer census for global `0x6712440` (prof.interval's value).
- `0x63ed090`/`0x63ed070` slow-path internals.
- The full option-parser FDE: only the prof / prof_leak_error windows
  are claimed; the rest of `0x6349be0..0x634eb7c` is characterized,
  not claimed.

## Next question (#260)

Continue leaf classification (181 remain); decode `0x63ef5e0` and
`0x63ef410`; census the writers of `0x6712440`; decode the
`0x63ed090`/`0x63ed070` slow paths.
