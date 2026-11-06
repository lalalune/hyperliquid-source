# RE-005 node 115 — the wheel insert's return: when the entry comes back instead of linking

Open edge 3 of `RE-005-node115-predicate-chain` (#2617):

> "The insert body 0x5cf6880's returned (rax, rdx) object
> semantics beyond the setter's use of it (an already-due
> entry handed back for immediate processing); its
> internals are exported but its producer conditions are
> not censused here."

This packet censuses the producer conditions. The insert
body `0x5cf6880` — called by the predicate-chain setter
`0x5cea7c0` at `0x5cea8d0`, its only direct caller in
`.text` — hands the entry back iff the converted value
is already due, and `rdx` is an entry pointer only on
that arm; on the link arm it is the deadline value
itself. The packet also continues the setter's store
census past the `0x5cea8d5` rebind, where #2617 stopped,
and pins the notify body `0x5ce09a0` the linked arm can
reach.

All three bodies are exported in full (`*.objdump.txt`);
digests, FDE extents, slot resolutions, strings, panic
Location statics, store censuses, the direct-caller
census and instruction-byte pins are re-derived from the
artifact by `tools/insert_return_static.py`.

## The insert contract

`0x5cf6880(rdi = &[wheel+0x8], rsi = entry)`. The entry
layout as this body sees it: `+0x00` previous link,
`+0x08` next link, `+0x10` last-written value, `+0x18`
value slot. The body loads `v = [entry+0x18]` and:

- traps if `v == -1`, through the assert-fail callee
  behind slot `0x64df770` (`0x1680bd0`), with the
  19-byte message at `0x94d3b8` ("Timer already fired")
  and the `entry.rs` Location static `0x64c6170`
  (line 417, col 27);
- stores `[entry+0x10] := v` at `0x5cf688f` — on every
  non-trapping path, before any return;
- compares `v` unsigned against the wheel elapsed
  field `[wheel+0x10]`, read as `[rdi+0x8]` because the
  sole caller passes `&[wheel+0x8]` — the same field
  the setter's level computation XORs the entry value
  against.

## The two return arms

**Already due — `(rax = 1, rdx = entry)`.** Producer
condition: `v <= [wheel+0x10]` (unsigned, `jbe` at
`0x5cf689f`). `eax` is preset to 1 at `0x5cf6897` and
the shared return at `0x5cf6958` moves `rsi` into
`rdx`; `rsi` is never written on this path, so `rdx`
is the entry pointer itself. Nothing is linked: the
body's complete store census shows the due arm
performs exactly one store, the `[entry+0x10] := v`
write that precedes the comparison, so an already-due
entry comes back with its `+0x10` field refreshed and
every link field untouched.

**Linked — `(rax = 0, rdx = v)`.** Otherwise the level
is `((bsr((v xor elapsed) | 0x3f) ^ 1) * 0x2b) >> 8`
with the pre-`bsr` input clamped to `0xffffffffe`; a
`bsr`-derived index above `0x23` (a level of 6 or
more) traps through slot `0x64df620` (`0x1680cbf`) with
the computed level and the `wheel/mod.rs` Location
static `0x64c6a30` (line 102, col 13) — a different
static from the setter's own level trap at line 130.
The bucket is `[wheel+0x8] + level * 0x410`; the slot
index is `(v >> shift) & 0x3f` with `shift = 6 *
[bucket+0x400]`, and the header word is trapped on
multiplication overflow (slot `0x64df870`, `level.rs`
173:19) and on `shift >= 0x40` (slot `0x64e0820`,
`level.rs` 173:6). If the computed slot's head already
is the entry, the body calls the linked-list guard
shim behind slot `0x64ecbd8` (`0x5ce82b8`, 51 B, extent
and digest pinned, not exported) with the
`linked_list.rs` Location static `0x64c5d70` (line 125,
col 9) and does not return — a double-link guard, not
a second return path. Otherwise it links the entry at
the slot head, sets the occupancy bit
`[bucket+0x408] |= 1 << slot index` at `0x5cf694c`,
and returns with `rdx = v` (loaded into `rsi` at
`0x5cf6955`, then moved to `rdx` by the shared return).

**Testable statement.** The setter's insert call hands
the entry back (`rax = 1`, `rdx` = the entry) iff the
converted value `v` satisfies `v <= [wheel+0x10]`
unsigned; it links the entry and returns (`rax = 0`,
`rdx = v`) in every other non-trapping case; and
`v == -1`, an out-of-range level, a corrupt bucket
header word, or an already-linked entry each trap
through the pinned Location statics instead of
returning. #2617's "(rax, rdx) object" phrasing is
exact only on the `rax == 1` arm.

## How the setter consumes each arm

#2617's setter census stopped at the rebind
`0x5cea8d5` (`mov r14, rdx`) and described the stores
after it as landing on a returned "other object". The
producer census above sharpens that: on the due arm
insert returns its `rsi` argument unchanged, and its
sole call site passes the entry the setter just stored
into — so the object is the setter's own `S+0x20`-based
entry. Over `[0x5cea8d5, 0x5ceaa17)` the setter performs
exactly five stores through `r14`:

- byte `[S+0x58] := 0` at `0x5cea8ec` — fired as due,
  where the timer-error arm writes 1;
- `[S+0x38] := -1` at `0x5cea8f1` — the value slot is
  consumed; this rewrites, later in the same call and
  on the due arm only, the same slot the setter's
  pre-call direct store at `0x5cea8c1` wrote the
  converted value into (the overwrite #2617
  attributed);
- `lock cmpxchg [S+0x50] |= 2` at `0x5cea907`, then the
  shared tail at `0x5cea90f`: if the `cmpxchg`'s old
  `[S+0x50]` was 0 the setter takes the pair
  (`[S+0x40]` → wake head, `[S+0x48]` → wake argument,
  `[S+0x40] := 0` at `0x5cea93e`, `xchg [S+0x50]` at
  `0x5cea948`), unlocks the wheel and, when the taken
  head is non-null, tail-calls `[head+0x8]` with the
  argument; if it was non-zero the setter only
  unlocks — the pair was already claimed, the race the
  post-call body `0x5ce91b0`'s swap on the same state
  word arbitrates (#2617). The `-1` re-check at
  `0x5cea8e2` cannot fire on this call path (insert
  traps on `v == -1` and the due arm does not rewrite
  `[entry+0x18]`); the shared tail is also the
  timer-error arm's continuation, which reaches it
  without the fire block and with the byte set to 1.

On the linked arm `r14` holds the integer `v`: the
setter compares `[wheel+0x28] - 1` against it unsigned
(`0x5cea96e..0x5cea978`) and, iff `v < [wheel+0x28]`,
calls the notify body `0x5ce09a0` on its `rsi` object
at `0x5cea97d`; it then unlocks the wheel (`lock
cmpxchg` at `0x5cea986`, contention via slot
`0x64e0f38`) and returns, with no store through the
entry after the insert call. (The one `rbx` store in
the range census, `[wheel+0x20]` at `0x5cea99b`, sits
in the pre-flag unlink fixup block at tail addresses,
reached only from `0x5cea87b`, before the call.)

## The notify body

`0x5ce09a0(rdi = object)`. If dword `[obj+0x44] != -1`
it calls `0x475aea0` on `&[obj+0x44]`, returns when
that returns null, and panic-formats through slot
`0x64df6a0` (`0x1680c30`) with the 25-byte message at
`0x94d466` ("failed to wake I/O driver") when it
returns non-null. Otherwise `rbx = [obj+0x0]` and it
`xchg`'s `[rbx+0x10] := 2`: old 0 or 2 returns at once;
old 1 claims the byte at `[rbx+0x20]` (`lock cmpxchg`
pair `0x5ce09f9`/`0x5ce0a04`, contention waiting via
slot `0x64e01f8` with a 1000000000 timeout) and, when
`[rbx+0x18]` is non-null, tail-jumps through slot
`0x64ec188` (`0x5bb42e0`) with `rdi = &[rbx+0x18]`; any
other old value panic-formats through slot `0x64df6b8`
(`0x1680e80`) with the `park.rs` Location static
`0x64c6f60` (line 187, col 18). Its complete
through-`rbx` store census is four stores.

## Precise negatives and boundaries

- A whole-`.text` scan for relative call/jump sites
  finds exactly one direct caller of `0x5cf6880` — the
  setter at `0x5cea8d0` — and no direct tail-jumps, so
  the producer conditions above are the complete
  direct-call picture. Calls through data-held pointers
  are not decidable from the artifact; none is known
  for this body, which sits on the conversion's
  tail-jump chain.
- The writer identities of the two wheel fields this
  chain reads but never writes — the flag byte at
  `[wheel+0x30]` (#2617 open edge 1) and the horizon
  field at `[wheel+0x28]` the linked arm compares
  against — remain untraced; this packet pins only
  their read sites, conditions and effects.
- The bucket body `0x5ce29a0`'s second direct caller
  at `0x5ceb06e` and the poll-side conditions under
  which entries are unlinked or bucket-inserted before
  the setter's flag test are not censused here.
- The runtime contents of the handle fields and of
  the notify object's fields are runtime data, not
  statically decidable (#2617 open edge 2, restated
  for the notify path); #2613's open edge 4 (gate
  re-invocation and `[record+0x1d8]` provenance) also
  remains open.

## Packet contents

- `records.json` — every derived record (owners,
  slots, strings, Location statics, constants, store
  censuses, caller census, pins, findings, the return
  table, open edges).
- `frames.txt` — the three FDE lines for the exported
  bodies.
- `insert.objdump.txt`, `setter.objdump.txt`,
  `notify.objdump.txt` — full Intel-syntax exports.
- `MANIFEST.sha256` — digests of the packet files.
- Tool: `tools/insert_return_static.py`; tests:
  `tests/test_insert_return_static.py`.
