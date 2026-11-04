# RE-005 node 115 — predicate post-check chain: who overwrites the S+0x38 sentinel

Open edge 1 of `RE-005-node115-gate-checkers` (#2613): on
checker_a's non-TLS path the shared predicate `0x5cf2d30`
stores `-1` at `[S+0x38]`, calls the conversion body
`0x5cead40`, then calls the body behind slot `0x64e0518`
(`0x5ce91b0`) on `&[S+0x40]`, and finally returns 1 iff
`[S+0x38] != -1`. Both callees run between the sentinel
store and the decision read; #2613 could not attribute the
overwrite. This packet attributes it exactly, states the
deciding condition testably, and pins what the builder's
`S+0x60`/`S+0x68` inputs are and how the conversion
consumes them.

All twelve bodies are exported in full (`*.objdump.txt`);
digests, FDE extents, slot resolutions, strings, statics,
store censuses and instruction-byte pins are re-derived
from the artifact by `tools/predicate_chain_static.py`.

## Attribution

**The conversion chain overwrites the sentinel; the
slot-`0x64e0518` callee cannot reach it.**

- The conversion body `0x5cead40` makes **no store
  through its argument at all** — its complete store
  census is four stack slots (`[rsp+0x8..0x20]`, the
  difference descriptor). It tail-jumps at `0x5ceae3e` to
  the setter body `0x5cea7c0` with `rcx = &[S+0x20]`,
  `rdx` = the converted value, `rsi` = the adjusted
  seconds, `rdi` = the wheel object at
  `handle + sel + 0x50`.
- The setter stores the converted value at **`0x5cea8c1`
  (`mov [r14+0x18], r12`, `r14 = &[S+0x20]`, i.e.
  `S+0x38`)** and at `0x5cea8c5` (`[r14+0x10]`, i.e.
  `S+0x30`), then inserts the entry via `0x5cf6880`.
- The post-call body `0x5ce91b0` is a once-cell swap on
  its argument `&[S+0x40]`: state `lock cmpxchg` at
  `+0x10`, pair store at `+0x0`/`+0x8`, contention steal
  at `+0x0`/`+0x10`. The sentinel sits at argument
  `-0x8`; the body's complete argument-store census is
  offsets `{0x0, 0x8, 0x10}` (plus one EH cleanup
  `cmpxchg` on the same `+0x10` word at `0x5ce9489`). No
  store in the body uses a negative displacement from
  the argument, so `S+0x38` is unreachable from it —
  a precise negative, not an untraced gap.
- The only other candidate, `0x5cf1d70`, is called at
  `0x5cf2e01` **before** the sentinel store at
  `0x5cf2e1e`, returns immediately when dword
  `[rdi] == 2` (the path in question), and in general
  writes only through the handle it drops (two
  `lock decq` stores), never through its argument.

## The deciding condition

The predicate pre-stores `[S+0x38] = -1` and byte
`[S+0x58] = 0` (block at `0x5cf2e06..0x5cf2e36`; the same
eight stores repeat in the timer-error landing pad at
`0x5cf2f99`, sentinel re-stored at `0x5cf2fb1`, as unwind
cleanup). The setter byte-locks the wheel (`lock
cmpxchg [rdi], 1` at `0x5cea7d8`; contention waits via
slot `0x64e01f8` → `0x5bb59d0` with timeout 1e9), then
decides on **the byte at `[wheel+0x30]`**, loaded at
`0x5cea881`:

| wheel byte `+0x30` | setter outcome | predicate result |
| --- | --- | --- |
| `== 0` | direct store: `[S+0x38]` := value at `0x5cea8c1`, `[S+0x30]` := value at `0x5cea8c5` | returns 1 |
| `!= 0`, value slot still `-1` at the test | no store, flag untouched | returns 0 |
| `!= 0`, value slot `!= -1` at the test | byte `[S+0x58]` := 1 at `0x5cea897`, `[S+0x38]` := `-1` restored at `0x5cea89c`, `[S+0x50] |= 2` via `cmpxchg` at `0x5cea8b7` | timer-error unwind |

Testable statement: through this path checker_a returns
nonzero **iff byte `[wheel+0x30] == 0`** at the setter's
flag test, where `wheel = [S+0x18] + sel + 0x50` and
`sel = byte [S+0x10] != 0 ? 0x160 : 0x240` — given the
conversion assert does not trap and the wheel lock is
acquired. The converted value's magnitude never
influences the return beyond being stored.

Before the flag test the setter unlinks or
bucket-inserts an entry whose value slot is already set:
level index from `bsr((value xor [wheel+0x10]) | 0x3f)`
clamped to `0xffffffffe`, bucket at
`[wheel+0x8] + level * 0x410`, insert body `0x5ce29a0`;
an out-of-range level traps at the wheel Location
static `0x64c6a48` — the artifact's own path string at
`0x446310` names `…/tokio/src/runtime/time/wheel/mod.rs`
(line 130, col 17). After a direct store, the insert
body `0x5cf6880` returns a `(rax, rdx)` pair; at
`0x5cea8d5` the setter rebinds `r14` to that returned
object and processes it — every `r14` store after that
site is on the returned object, not on S, which is why
the setter census stops at the rebind.

## The builder's S+0x60/S+0x68: a (sec, nsec) deadline

Builder `0x5cf2150(rdi = S, rsi = duration sec, edx =
duration nsec, rcx = descriptor static 0x644dc28)`
stores exactly five fields (`0x5cf2261..0x5cf226f`):
`[S+0x60]` = deadline seconds (qword), `[S+0x68]` =
deadline nanoseconds (dword), `[S+0x0]` = accessor flag,
`[S+0x8]` = handle, `[S+0x10]` = 2.

- The deadline is `clock + duration`: the base-value
  body `0x5c842e0` is called with `edi = 1` and forwards
  that 1 untouched as the clock id of the GLOB_DAT slot
  `0x64e1248` — `clock_gettime` — returning its
  `(sec, nsec)` pair (unwrap trap on error, message at
  `0x949294`; trap if `nsec >= 1e9`). Seconds add is
  checked; the overflow fallback re-reads the clock and
  adds `946080000` before re-normalising.
- Nanoseconds are normalised into `[0, 1e9)` with carry
  into the seconds.
- The accessor behind slot `0x64e0848` (`0x5cf2b50`) is
  called with the descriptor static (two panic Location
  statics for `base/src/lu.rs`, relocated pointer
  `0x4326c1`): it returns `rax ∈ {0, 1}` (strong/weak
  flag) and `rdx` = the calling thread's current handle
  pointer, read from the TLS cell at `fs:-0x1130+0x10`
  after a `lock xadd` refcount increment. The builder
  asserts `[handle+sel+0x90] != 1_000_000_000` through
  the same trap as the conversion.

The conversion consumes the pair as integers, never as
memory: `rsi = [S+0x60]` is the seconds count
(incremented, with an overflow trap at `0x5ceae5c` —
"overflow when adding duration to instant" — on the
carry arm), `edx = dword [S+0x68]` is adjusted by
`-999000001` (when `>= 999000001`) or `+999999`. It
then differences the pair against the handle's stored
`(sec, nsec)` at `[handle+sel+0x88]` /
`[handle+sel+0x90]` via the difference body `0x5c84210`
(`{sign, diff sec, diff nsec}` out; swap-recursive on
`A < B`; "overflow in Duration::new" panic), and forms
the converted value as `diff_sec * 1000 +
(diff_nsec * 1125899907 >> 50) + carry` — a
millisecond-shaped count — forced to 0 when the
difference sign is nonzero and saturated at
`0xfffffffffffffffd`.

Both the conversion (at `0x5cead6a` and again at
`0x5ceaddd`) and the builder trap through the
assert-fail callee behind slot `0x64df770` →
`0x1680bd0` if dword `[handle+sel+0x90] == 1_000_000_000`,
with the 115-byte message at `0x94ca6b`: "A Tokio 1.x
context was found, but timers are disabled. Call
`enable_time` on the runtime builder to enable
timers." — the artifact's own identification of this
handle as a timer context.

## Precise negatives and boundaries

- `0x5ce91b0` cannot write `S+0x38` (argument `-0x8`;
  census above) — proven, not untraced.
- `0x5cf1d70` cannot be the writer (call order, tag-2
  early return, no through-argument store) — proven.
- Not statically decidable here: the source identity of
  the wheel byte at `[wheel+0x30]` (which writer sets
  it, on what event); the runtime contents of
  `[handle+sel+0x88]`/`[handle+sel+0x90]` and of the TLS
  accessor cell; the producer conditions of the insert
  body's returned `(rax, rdx)` object beyond the
  setter's use of it. These are runtime-data and
  producer-side boundaries, recorded in
  `records.json:open_edges`.

## Packet contents

- Owners (all exported in full): `checker_a`
  (context), `builder`, `predicate`, `normalise`,
  `accessor`, `basevalue`, `desccall`, `conversion`,
  `setter`, `postcall`, `insert`, `bucket`.
- `records.json`: digests/FDE extents, slot resolutions
  (including the `clock_gettime` GLOB_DAT slot),
  strings, descriptor and wheel Location statics,
  constants, the six store censuses, 18 instruction-byte
  pins, findings, the three-row decision table, open
  edges.
- `frames.txt`: the twelve owners' FDE lines.
- Tool: `tools/predicate_chain_static.py`; tests:
  `tests/test_predicate_chain_static.py`. Verify mode
  prints `{"matches": true, "packet":
  "RE-005-node115-predicate-chain"}`.
