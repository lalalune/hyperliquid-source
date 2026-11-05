# RE-005 node115 lu.rs LazyLock accessor consumers

Status: static evidence packet for one bounded RE-005 question. The
companion verifier is `tools/lu_lazylock_consumers.py`; retained
exports sit beside this file and are hash-bound by
`MANIFEST.sha256`.

## Question

PR #2999 pinned the base crate's `std::sync::LazyLock` cell at
`0x64f01c0` (initializer `0x1568de0`, state dword at `0x64f01d8`)
and left two things open: what the cached 24-byte value denotes at
source level, and what its only direct reader does with it. That
reader is the accessor `0x1560a40..0x1560aab`, reached through GOT
slot `0x64e0b20`, which returns the cell's +8/+0x10 words at 100
call sites in 65 bodies. What do those 65 bodies use the returned
pair for — do they dereference it as a handle, read it as integer
settings, branch on it — and what does the consumer side say
about the value itself?

## Result

**No consumer reads the pair as data. At all 100 call sites the
returned (pointer, length) is discarded: the calls survive in the
binary because the accessor is effectful (it forces the once and
panics on poison), not because any caller wants the string. And
the value is the base crate's build-mode string: the initializer
belongs to `base/src/build_mode.rs`.**

The fate of the pair, per site (method: fall-through scan of both
result registers, a block-level CFG walk inside each body, and
manual reading of every flagged exception; windows retained in
`consumer-windows.txt`):

| context | sites | what the site looks like |
|---|---|---|
| drop glue | 38 | the call sits inside a generated drop/cleanup sequence — an adjacent TLS-state store, a reference-count decrement, or the field-dispatch finalizer `0x452a890` runs right around it, on the pair of a *different* value the body is tearing down |
| statement | 54 | ordinary statement position; both registers are overwritten or simply never read and execution continues |
| error exit | 6 | the call immediately precedes loading an error tag/message and jumping to the shared exit (e.g. the checked-arithmetic overflow arm loading error `0x29`, and the Hyperliquidity error arms in `0x38bc000`) |
| unwind cleanup | 2 | the call sits in a landing-pad cleanup block of `base/src/file_mod_time_tracker.rs`'s body `0x1509b70`, in a sequence of getter/drop calls that ends in `ud2` |

No site dereferences the returned pointer, compares or
bounds-checks the returned length, passes the pair on to a
callee, or stores it anywhere. The apparent exceptions dissolve
on inspection: a `mov %rax,%r15` after some sites moves the
result of the *next* call; the shared-epilogue jumps carry the
enclosing body's own return value in `rdx`, not the accessor's.

19 of the 65 bodies also carry inlined ensure blocks for the same
cell (32 address references in total): each passes only the cell
*address* into a stack-built closure environment for the once
machinery. They never load the value words either — matching
PR #2999's whole-`.text` census, which found the words loaded
only inside the accessor.

## The value, from the initializer out

- The accessor returns `*(cell+8)` in `rax` and `*(cell+0x10)` in
  `rdx` (loads at `0x1560a4a` / `0x1560a51`). It pointedly does
  not return the word at cell+0.
- The initializer's last act (`0x1569609..0x156961a`) stores its
  24-byte sret result as (length, pointer, length): read in cell
  order the value is a `String` — capacity, data pointer, length
  — and the word the accessor skips is the capacity. The 24-byte
  value of PR #2999 is a `String`, and the accessor is a
  `&'static str` getter over it.
- Two `panic::Location` records inside the initializer decode to
  `base/src/build_mode.rs:28:13` and `base/src/build_mode.rs:30:26`
  (records at `0x63fe3a8` / `0x63fe390`; the file string is 22
  bytes; the path pointer is supplied by a RELATIVE relocation at
  each record). The file string occurs exactly once in the
  binary, and it sits beside `base/src/lu.rs` — the value belongs
  to a sibling module of the same crate, not to the runtime
  builder.
- The initializer starts from a default (0, 1, 0) triple (stores
  at `0x1568df6..0x1568e10`), builds the process-argument iterator
  through the adjacent slots `0x64e1290` / `0x64e1298`, and walks
  the arguments as (pointer, length) pairs, dispatching first on
  a `--` prefix (compare at `0x1568f40`). For the selected path
  argument it requires `!arg.ends_with('/')`: the assertion
  message (37 bytes at `0x4676f8`) is loaded at `0x1569663` and
  its panic call passes the line-28 Location record. It searches
  for the `/cham/` component (byte compares at `0x1568f62` /
  `0x1568f6d` against the 6-byte literal at `0x4676f2`); a second
  panic site (`0x156969b`) passes the line-30 Location as the
  last argument of a bounds-checked operation in the same tail.
  The surviving candidate is rebuilt byte-by-byte through the
  transform function `0x150caf0..0x150cd87`, a UTF-8 walk
  applying a per-character lowercase mapping.
- Packed immediately after the assertion message sit the three
  candidate literals `debug` (5 bytes at `0x46771d`), `release`
  (7 at `0x467722`) and `run-client` (10 at `0x467729`) — the
  build-mode vocabulary the derived string is checked against.

Reading: the `LazyLock` caches the node's build-mode string,
derived once from the invocation path (the component after
`/cham/`), and the getter exists so any code in the base and l1
crates can force or observe that initialization. In this build
the compiled callers keep the call and drop the string.

## Evidence

- `tools/lu_lazylock_consumers.py` recomputes everything from
  the pinned binary: the slot relocation, the accessor /
  initializer / transform body pins (FDE extent + SHA-256), all
  18 byte pins, both `build_mode.rs` Locations, the five packed
  literals, the whole-`.text` census (100 indirect-call sites,
  65 bodies, no direct-call / load / jump forms), the inlined
  ensure-block count per body, and the classification table
  bound to the census site set.
- `tests/test_lu_lazylock_consumers.py`: run against the
  materialised pinned artifact — all pass, 0 skipped;
  regeneration matches the retained packet byte for byte.
- Packet: `research/work-items/RE-005-node115-lu-lazylock-consumers/`
  (README, records.json, frames, accessor and initializer objdump
  exports, per-site consumer windows, MANIFEST.sha256).

## Boundaries

- The exact command-line argument the initializer selects, and
  the source name of the `LazyLock` static and its getter, are
  not pinned: no Location inside the initializer names the
  static, and which of the candidate literals a given code path
  compares against is not traced end to end.
- Whether wrapper a's kind-1 arm is ever selected at run time
  stays open, as PR #2969 left it.
- The fate classification is a static result about these 100
  sites. It does not claim the string is unread anywhere in
  principle — only that none of the accessor's compiled call
  sites, and none of the inlined ensure blocks, ever load its
  words.

## Relation to PR #2999

No contradiction: the census is identical (100 sites, the same
65 bodies) and the accessor and initializer pins match byte for
byte. This packet refines two of #2999's open points — the
24-byte value is a `String` whose capacity word the accessor
skips, and its initializer belongs to `base/src/build_mode.rs` —
and closes the consumer question #2999 recorded but did not
answer.
