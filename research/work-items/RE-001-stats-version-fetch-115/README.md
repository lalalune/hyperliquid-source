# RE-001: stats version-key fetch 0x606e3a0 with its produce dispatch, default produce and sole caller (node #115)

## Bounded question

How does the routine at `0x606e3a0` select its key by mode, dispatch
the produce call between the source vtable slots `0xe8` and `0xf0`,
and turn the produced value into an out `u64` or a `NotFound`
Status — and what does its sole caller, the persistent-stats
column-family open at `0x5e61ad0`, do with the two fetched version
numbers?

## Answer

The fetch is `fetch(out_status, source, mode, out_u64)` and returns
the out Status. The mode selects the lookup key: 0 leaves the key
empty, 1 uses `__persistent_stats_format_version__` (35 bytes),
2 uses `__persistent_stats_compatible_version__` (39 bytes);
mode > 2 returns `InvalidArgument` with
`Invalid stats version key type provided`. It initializes the same
`0x90`-byte state the insert uses (`0x60b21f0`), reads the bound
with the getter `0x5d532d0` (`*(source+0xac0)`), then dispatches
the produce call: it loads the source vtable slot `0xe8` and
compares it against the GOT entry `0x64ed288` (RELATIVE addend
`0x5d33a90`, the default produce). When the slot differs it calls
the slot directly with the value string; when it equals the
default it calls slot `0xf0` instead, with a replacement view, a
cleanup chain and an aux bundle. The result is decided by the
produce out flag, the aux flag and the value length: a produced
value is decimal-parsed into `*out_u64` and the Status is zeroed
(OK); otherwise the Status is `NotFound` with the message
`Persistent stats version key <key> not found.`, plus `: <key>`
appended by the Status builder when the key is non-empty. The
sole caller fetches both version keys (mode 1, then mode 2) and
proceeds only when both Statuses are OK; otherwise it logs
`Recreating persistent stats column family since reading
persistent stats version key failed. Format key: %s, compatible
key: %s` (db_impl_open.cc:744) and recreates the column family.

## The caller 0x5e61ad0 (30777 bytes)

Arguments: `rdi` out Status, `rsi` source. Only the two call
sites, the both-OK gate and the error-log call are pinned here;
the caller's remaining body is not mapped in this packet.

1. It acquires the instrumented lock `0x60d5390` on `source+0x700`
   (released with `0x60d52f0`) and reads the flag byte at
   `source+0xac8`; the version reads run only when that flag is
   nonzero.
2. Mode 1 at `0x5e61b9e`: `fetch(&status1 at rsp+0x40, source, 1,
   &value1 at rsp+0x28)`. Mode 2 at `0x5e61bc6`: `fetch(&status2
   at rsp+0x50, source, 2, &value2 at rsp+0x30)`. Both out `u64`
   slots are zeroed before their call.
3. Both-OK gate: the code bytes at `rsp+0x40` and `rsp+0x50` are
   ORed; both zero jumps to `0x5e62360` (the success path).
   Otherwise it builds two strings with `0x61cfed0` and calls the
   log routine `0x5fcf060` with (`edi=2`, format at `0x95e370`,
   file at `0x960600`, the two fetched strings) — the
   `Recreating persistent stats column family...` message — and
   recreates the column family.

## The fetch 0x606e3a0 (1673 bytes)

Arguments: `rdi` out Status (16 bytes: code `u32@+0`, subcode
`u16@+4`, message pointer `+0x8`), `rsi` source, `edx` mode,
`rcx` out `u64`. Returns the out Status. Frame `sub $0x1c8,%rsp`
with a stack canary.

1. Mode dispatch: `cmp $0x2,%edx; ja 0x606e7b8` — mode > 2 builds
   `InvalidArgument` (code 4) through the shared builder
   `0x61cf670` with the format at `0x95fbe8` (39 bytes)
   `Invalid stats version key type provided` and the empty second
   view `{ptr 0x4376fd, len 0}`, then jumps to the epilogue.
   Otherwise the key string at `rsp+0x60` is selected: mode 1
   assigns the format-version record (`0x65061c0`, 35 bytes) at
   `0x606e8d0`, mode 2 assigns the compatible-version record
   (`0x65061a0`, 39 bytes) at `0x606e870`, mode 0 leaves the key
   empty. No in-binary caller passes mode 0.
2. Common path at `0x606e415`: initialize the `0x90`-byte state
   at `rsp+0x120` with `0x60b21f0`, then write byte 1 at
   `state+0x2c`; read the bound with the getter `0x5d532d0`.
3. Produce dispatch: `r12 = *(source vtable + 0xe8)`, compared
   against the GOT entry `0x64ed288` (RELATIVE addend
   `0x5d33a90`). When different, the slot is called directly at
   `0x606e8f0` with `(out=&context at rsp+0x30, source, state,
   bound, key view at rsp+0x50, value string at rsp+0x80)`.
   When equal, the default path builds the replacement view
   `{ptr 0x4376fd, len 0}` at `rsp+0xc0`, initializes the cleanup
   chain at `rsp+0xd0` with `0x61bd0c0`, builds the aux bundle at
   `rsp+0xf0` (empty string, target = the value string, flag 0),
   and calls slot `0xf0` at `0x606e51b` with `(out=&context,
   source, state, bound, key view, replacement view at rsp+0xc0)`.
4. Result protocol (context at `rsp+0x30`: flag byte `+0x00`,
   heap pointer `+0x08`):
   - Flag nonzero: `NotFound`, message built as below.
   - Flag zero and aux flag (context `+0xe8`) nonzero (0xf0
     path only): `value.replace(0, value length, replacement
     ptr, replacement len)` — the string at `rsp+0xc0`
     supplies the replacement — then apply the value rule.
   - Flag zero and value length nonzero: decimal-parse the value
     with `0x61d1540` (whitespace, optional sign, `K`/`M`/`G`/`T`
     suffix shifts; throws on no digits or overflow) into
     `*out_u64`, then zero the 16-byte out Status (OK) and jump
     to the epilogue.
   - Flag zero and value length zero: `NotFound`, same message.
5. `NotFound` message build at `0x606e572`: reserve
   `key length + 0x1d` in a string at `rsp+0xa0`, append the
   literal at `0x440a1e` (29 bytes)
   `Persistent stats version key `, append the key, append the
   literal at `0x4383c8` (11 bytes) ` not found.`, move-construct
   the result into the storage at `rsp+0xc0` (the cleanup chain
   there is already destroyed), and call the builder with
   `(out, code 1, subcode 0, message view, key view, 0)`. The
   builder stores `message + ": " + key` when the key is
   non-empty (modes 1 and 2 store the key twice); mode 0 stores
   `Persistent stats version key  not found.` with no append.
6. Epilogue: free the heap pointer at `rsp+0x38` with `delete[]`
   when non-null, dispose the value string and the key string,
   call the state callback at `rsp+0x168` with
   `(rsp+0x158, rsp+0x158, 3)` when non-null, check the canary,
   return the out Status.

## The exception cleanup 0x606e2eb (176 bytes)

The eight landing pads at the end of `main.txt`
(`0x606e9c9..0x606ea24`) jump into this block at eight entry
points (`0x606e2eb`, `0x606e2f5`, `0x606e30a`, `0x606e331`,
`0x606e356`, `0x606e361`, `0x606e381`, `0x606e38e`), each
carrying the exception object in `rbx` or `rbp`. It frees the
heap pointer, disposes the aux string, destroys the chain,
disposes the value string, calls the state callback, disposes
the key string, checks the canary, then `_Unwind_Resume`. The
normal epilogue inlines the same steps except the resume.

## The default produce 0x5d33a90 (727 bytes)

The canonical slot-`0xe8` value, installed at slot `0xe8` of six
vtables (`0x64c82c0`, `0x64c9368`, `0x64cb0e0`, `0x64cb5c0`,
`0x64cbbc0`, `0x64d97d0`) plus the GOT entry `0x64ed288`. It has
no direct callers. Arguments are the same six as the fetch's
produce call: `(out, source, state, bound, key view, value
string)`.

1. It builds its own aux view `{ptr 0x4376fd, len 0}` at
   `rsp+0x10` and initializes its own cleanup chain at
   `rsp+0x20` with `0x61bd0c0`.
2. Chain chase: it reads the slot `0xf0` of the source, then of
   `*(source+0x8)`, then of `*(that+0x8)`, comparing each
   against the canonical `0x5d2d0e0` (GOT `0x64ed070`); the first
   non-canonical slot is called with the same six arguments. If
   all three are canonical it calls the fourth hop's slot `0xf0`
   unconditionally.
3. After the call returns: when the out flag byte is 0 and the
   local aux flag byte (`rsp+0x68`) is nonzero, it runs
   `value.replace(0, value length, aux ptr, aux len)` — the same
   replacement rule as the fetch's 0xf0 path — then destroys the
   chain, disposes the aux string, checks the canary and returns
   the out pointer.

## The forward produce 0x5d2d0e0 (71 bytes)

The canonical slot-`0xf0` value, installed at slot `0xf0` of the
first of those vtables (`0x64c82c0`) plus the GOT entry
`0x64ed070`. It has no direct callers. It calls
`*(rsi+0x8)`'s slot `0xf0` with the same six arguments (the out
pointer preserved in `rbx`) and returns the out pointer — a
one-hop forwarder down the `+0x8` source chain.

## The cleanup chain 0x61bd0c0 / 0x61bd0e0

The chain node is `{callback +0x00, arg1 +0x08, arg2 +0x10,
next +0x18}` (32 bytes). The initializer `0x61bd0c0` (20 bytes)
writes callback 0 and next 0. The destructor `0x61bd0e0`
(81 bytes) returns at once on a null callback; otherwise it
calls the callback with `(arg1, arg2)`, then walks the `next`
list calling each node's callback and freeing each `0x20`-byte
node. The fetch and the default produce each initialize one
chain empty before their slot-`0xf0` call and destroy it after
the call returns; the callee is the only writer of the chain's
entries.

## The version keys and their initializer

Two `{ptr, len}` records live in BSS and are built once by the
static initializer `0x606f950` (registered in `.init_array` at
`0x63f3990`, stored qword at file offset `0x7468`) from literals
via the string constructor `0x5f204e0`:

- `0x65061c0`: `__persistent_stats_format_version__` (35 bytes,
  literal at `0x95c460`) — the mode-1 key.
- `0x65061a0`: `__persistent_stats_compatible_version__` (39 bytes,
  literal at `0x96ae00`) — the mode-2 key.

## Re-shipped helpers

- `state_init.txt`: the state initializer `0x60b21f0`,
  byte-identical from PR #3237.
- `bound_getter.txt`: the bound getter `0x5d532d0`,
  byte-identical from PR #3237.
- `initializer.txt`: the version-key initializer `0x606f950`,
  byte-identical from PR #3237.
- `string_ctor.txt`: the string constructor `0x5f204e0`,
  byte-identical from PR #3237.
- `status_builder.txt`: the Status builder `0x61cf670`,
  byte-identical from PR #3237.
- `parse_u64.txt`: the decimal parser `0x61d1540`,
  byte-identical from PR #3196 (via #3237).

The instrumented acquire `0x606ca40` is mapped end to end in
its own packet and is only referenced here as the lock the
caller takes; the unlock wrapper `0x60d52f0` and the log routine
`0x5fcf060` are likewise referenced, not re-claimed.

## Verification

`verify.py` checks the work binary digest against the provenance
entry, the manifest, excerpt regeneration byte-for-byte from fresh
objdump runs (re-shipped excerpts by pinned SHA-256), every excerpt
instruction byte-for-byte against the raw binary, spot instructions,
the FDE ranges in `frames.txt` against a fresh frame dump, the
relocation set (10 lines: the seven `0x5d33a90` records, the two
`0x5d2d0e0` records and the one `0x606f950` record), the literals,
the census reproduction (12 pinned routines; `callers.tsv` holds
1296 rows), the semantic records (re-derived from the excerpts:
the mode dispatch, the produce dispatch, the chain chase, the
forward rule, the aux replace, the eight landing pads, the state
init stores, the message composition, the caller gate), and the
model tests in `tests/test_stats_version_fetch_115.py`.

## Not claimed

- The concrete dynamic type behind the source object's vtable
  slots (produce `0xe8`, produce `0xf0`).
- Which in-binary caller passes mode 0 (empty key); only modes 1
  and 2 are used by the sole caller.
- The full extent of the produce context struct beyond the pinned
  offsets (flag `+0x00`, heap pointer `+0x08`, message view
  `+0x10`, key view `+0x20`, key string `+0x30`, value string
  `+0x50`, temp message string `+0x70`, replacement view `+0x90`,
  chain `+0xa0`, aux string `+0xc0`, aux target `+0xe0`, aux flag
  `+0xe8`).
- How the `0xf0` callee reaches the aux flag and replacement view
  beyond the pointers it receives (context pointer `rdi`, state
  `rdx`, replacement view `r9`).
- The caller's remaining ~30 KB body beyond the two call sites,
  the both-OK gate and the error-log call (the success path at
  `0x5e62360`, the slot-`0x38`/`0x48` calls and the `0x5e57ae0`
  Status check are not mapped here).
- The sibling routine `0x606ead0`, called by the caller at
  `0x5e61cdb`.
- What the flag byte at source `+0x4c9` (mapped in PR #3237) means
  beyond selecting node type A versus B.
- Behaviour on a null source pointer (the fetch reads
  `source+0xac0` through the bound getter and the source vtable
  unconditionally).

The mnemonics in the excerpts (`endbr64` included) are genuine
instructions present in the target binary, not placeholders.
