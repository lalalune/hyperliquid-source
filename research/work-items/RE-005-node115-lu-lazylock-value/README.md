# RE-005 node115 lu.rs LazyLock global

Status: static evidence packet for one bounded RE-005 question. The
companion verifier is `tools/lu_lazylock_global_static.py`;
retained exports sit beside this file and are hash-bound by
`MANIFEST.sha256`.

## Question

The builder caller wrapper identities packet (PR #2969) pinned
wrapper a (`0x15d6fd0..0x15d8447`, 5239 bytes), a runtime-runner
function of the base crate in `base/src/lu.rs`. Its kind-1 arm
first consults a process-global once: when the state dword at
`0x64f01d8` is nonzero it calls `call_once_force` (GOT slot
`0x64df9f0` -> sys body `0x5c87d50`) with the once at `0x64f01d8`
and a closure environment holding the address of a global cell at
`0x64f01c0` (closure statics `0x63fe250` / `0x63fe278`), and only
then builds its runtime. That packet left open what the once
guards: does it cache the runtime wrapper a builds -- and if so
in what form -- or does it guard something else?

## Result

**The once does not cache wrapper a's runtime. It is the once of
a `std::sync::LazyLock` whose 24-byte value is produced by an
initializer function that has nothing to do with the runtime
builder, and wrapper a never reads the cached value.**

The global's static shape:

- Cell `0x64f01c0`, 24 bytes in `.data`, file value all zero,
  immediately followed by the once state dword at `0x64f01d8`,
  file value 3. The sys once body pins the state encoding:
  0 = COMPLETED, 1 = RUNNING, 2 = POISONED, 3 = INCOMPLETE, with
  bit `0x4` as a futex waiter flag (claim by `lock cmpxchg` at
  `0x5c87d93`, success write-back `xchg` at `0x5c87e4a` storing
  the default OnceState byte 0 prepared at `0x5c87e2e`, panic
  path storing 2 at `0x5c87f3f`/`0x5c87f44`).
- Exactly one relocation in the whole binary touches the
  32-byte range: an `R_X86_64_RELATIVE` entry at the cell whose
  addend is `0x1568de0`. At load time the cell's first qword
  therefore holds that function pointer -- the `LazyLock`
  initializer slot. The only `imm64` occurrence of the cell
  address in the file is that entry's own `r_offset` field in
  `.rela.dyn`.

The closure (vtable `0x63fe250`: drop word 0, size 8, align 8,
`call_once` shim `0x1568980`, `call_mut` shim `0x155fd80`): both
shims are byte-pattern identical. Each takes the fn pointer out
of the caller slot (zeroing it; a null pointer panics with
Location `std/src/sync/once.rs:219:49` through slot `0x64df830`
-> `0x1680c10`), checks the OnceState poisoned byte (set ->
calls the poison helper through slot `0x64dffd0`), otherwise
calls the fn pointer from the cell through a 24-byte sret buffer
and writes the 24-byte result back over the cell (`movups` at
+0, `mov` at +0x10). The call site carries Location
`std/src/sync/once.rs:219:20`. The poison helper (`0x5c9d1a0`,
29 bytes) raises the message `LazyLock instance has previously
been poisoned` (46 bytes at `0x949c9e`) with Location
`std/src/sync/lazy_lock.rs:410:5` -- this message and Location,
not the static shape alone, are what identify the global as a
`LazyLock`.

The initializer (`0x1568de0..0x156971c`, 2364 bytes) never calls
the runtime builder `0x5cf9600`, the cfg ctor `0x5cf93f0`, or
the builder slot `0x64e1760`; its full direct and slot-indirect
call census is retained in `records.json` (helper bodies
`0x150caf0`, `0x153e560`, `0x156b230`, slot targets for
allocation, `memcpy` and deallocation among them). It has no
direct callers at all: it is reached only through the fn
pointer the deposit relocation leaves in the cell.

Wrapper a's use of the pair is exactly three references: the
state load at `0x15d6fec`, and the slow path's lea pair (cell at
`0x15d71b0`, once at `0x15d71cf`). The slow path calls the sys
once with the force flag `esi = 1` and then jumps
unconditionally back to `0x15d6ffa`, falling into the same build
the fast path takes: `cfg_ctor` with kind 1 (direct call at
`0x15d7007`), builder through the slot at `0x15d7026`. No byte
of the cached value is read anywhere in the body, the accessor
slot is never called from it, and the runtime object is built
in wrapper a's own frame on every call. Once the `LazyLock` is
initialized, wrapper a's forced call is a no-op and changes
nothing about the build that follows it.

The cached value's only direct reader is an accessor body
(`0x1560a40..0x1560aab`, 107 bytes), reached through GOT slot
`0x64e0b20` (100 call sites in 65 bodies, none of them wrapper
a; it has no direct callers). When the state is 0 it returns the
cell's +8 and +0x10 qwords as an `rax:rdx` pair; otherwise it
runs the same forced once inline and then reads the same two
words. The +0 word -- the initializer pointer itself until the
product overwrites it -- is not returned.

## Census

A whole-`.text` census of validated RIP-relative references
(ModRM mod=00, rm=101) to the 32-byte range
[`0x64f01c0`, `0x64f01e0`) finds 1713 references in 421 distinct
bodies and closes the remaining paths:

| target | opcode | count | meaning |
|---|---|---|---|
| `0x64f01c0` (cell) | `0x8d` lea | 569 | ensure-init env setup |
| `0x64f01d8` (state) | `0x8b` load | 572 | fast-path state check |
| `0x64f01d8` (state) | `0x8d` lea | 568 | ensure-init once argument |
| `0x64f01c8` (cell +8) | `0x8b` load | 2 | accessor fast/slow reads |
| `0x64f01d0` (cell +0x10) | `0x8b` load | 2 | accessor fast/slow reads |

- Store-opcode references: 0. Writing the cell requires first
  materializing its address; in `.text` that happens only at
  the 569 lea sites, and every one of the 421 bodies containing
  a cell lea carries the identical six-feature ensure-init set
  (state load, lea cell, lea once, lea vtable, lea location,
  call through the sys once slot `0x64df9f0` -- 1553 such call
  sites in total). Inside those calls the only writers are the
  closure shims' write-back of the initializer's product and
  the sys body's state transitions through its `rdi` argument.
- One representative inlined site is retained as an owner
  (`0x150bd10..0x150bdca`): state check, identical slow-path
  setup, then the body's own continuation `0x150c590` -- the
  pattern the other 420 bodies share.
- The closure vtable and call Location are lea-referenced 712
  and 725 times respectively -- more than this pair's 421
  bodies: 41 further bodies reference the same statics with
  other cells (other statics sharing the monomorphized
  closure), and 443 bodies call the sys once slot with no
  statics at all (register-passed onces). Those are context,
  not part of this pair.

## Boundaries

- What the initializer's 24-byte product denotes at source
  level -- which `LazyLock` static of the base crate this is --
  is **not** pinned. No Location inside the initializer names
  the static, and nearby string literals are not attributed to
  it here.
- Whether the dispatcher that reaches wrapper a ever selects
  the kind-1 arm at run time stays open, exactly as PR #2969
  left it; every statement in this packet is about the linked
  code paths, not observed execution.
- The other statics sharing this closure (the 41 bodies above)
  are outside this packet; their cells are not censused here.

## Verifier

`tools/lu_lazylock_global_static.py` re-derives every pin in
`records.json` from the materialized artifact: owner FDE
extents and body hashes, 69 byte pins, the deposit relocation,
the state encoding sites, the closure vtable, the three
Locations, both poison messages, the initializer's call census,
and the whole-`.text` census. Run the retained tests in the
materialized state:

    python3 -m unittest tests.test_lu_lazylock_global_static

No captured code was executed; this is static analysis of the
pinned node #115 distribution only.
