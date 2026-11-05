# RE-005 node115 builder caller wrapper identities

Status: static evidence packet for one bounded RE-005 question. The
companion verifier is `tools/builder_wrapper_identities_static.py`;
retained exports sit beside this file and are hash-bound by
`MANIFEST.sha256`.

## Question

The tag-3 supply packet (PR #2950) pinned the driver builder
`0x5cf9600` (vendored tokio runtime `Builder::build`): its only
callers are two bodies reached through the GOT slot `0x64e1760`,
and both overwrite the builder config's u16 at `+0xe5` with
`0x0101`. It left the two caller bodies unidentified. What are
they at source level, and how do they relate?

## Result

**Wrapper a (`0x15d6fd0..0x15d8447`, 5239 bytes) is a
runtime-runner function of the base crate, source file
`base/src/lu.rs`.** Its own panic Locations name that file three
times: the two builder-error sites are `lu.rs:55:40` and
`lu.rs:58:76`, and its nested-runtime panic site is `lu.rs:60:13`.
The body is arm-selected by its entry flag in `edi`:

- `edi != 0`: the body first reads a process-global once state
  dword at `0x64f01d8`; when it is nonzero it calls
  `call_once_force` (slot `0x64df9f0` -> `0x5c87d50`) with the
  once at `0x64f01d8` and a closure environment holding the
  address of a global cell at `0x64f01c0` (closure statics
  `0x63fe250` / `0x63fe278`), then falls into the build:
  `cfg_ctor` with kind argument 1, the `0x0101` overwrite at
  `cfg +0xe5`, the builder through the slot, a cfg drop
  (`0x5cf1af0`). A builder error result (tag dword 2) panics
  through the message thunk (slot `0x64df6a0` -> `0x1680c30`)
  with the message `tokio_run` (9 bytes at `0x469c40`) and
  Location `lu.rs:55:40`.
- `edi == 0`: the same build with `cfg_ctor` kind argument 0
  and no once consultation; the error panic carries Location
  `lu.rs:58:76` (same message, same error vtable `0x64015d0`).

After either build the body copies the `0x70`-byte runtime
object to `rsp+0x70`, `memcpy`s (slot `0x64df508` ->
`memcpy@GLIBC`) its second argument's `0x3d0` bytes into the
frame, and enters the vendored runtime context (TLS state byte
at `fs:-0x1130+0x48`; the inlined scheduler code carries
`current_thread/mod.rs` and `multi_thread/mod.rs` Locations).
Its only caller is a 67-byte adapter (`0x155fa10`) that expands
a `0x30`-byte input into the `0x3d0`-byte argument (zero byte at
`+0x3c8`) and passes `edi = 0` — so as linked, only the kind-0
arm is exercised. The adapter has no direct callers: it is
called once, through its function-pointer GOT slot `0x64e1190`
(site `0x15b907d`), by a 498-byte list-walking dispatcher
(`0x15b8fd0`) that is itself recorded in a static
`.data.rel.ro` table (cell `0x6400548`).

**Wrapper b (`0x2ae1690..0x2ae27b2`, 4386 bytes) is the node
binary's principal entry function.** The ELF entry `_start`
(`0x1419300`) passes `main = 0x2cef8f0` to `__libc_start_main`
(slot `0x64df458`); that 39-byte compiler main shim registers
the user main `0x2cd8370` with std's `lang_start` (slot
`0x64e6c30` -> `0x5c99970`, main vtable `0x6440b48`); the user
main zero-builds a `0x2c40`-byte struct (explicit zero byte at
struct `+0x21a`) and calls wrapper b with its address — wrapper
b's only caller. Wrapper b builds exactly one runtime:
`cfg_ctor` kind 1, the `0x0101` overwrite, the builder through
the slot; on a tag-2 error it panics through the same thunk
with the standard 43-byte unwrap message (`0x605542`) and
Location `node/src/utils.rs:66:70`. It then `memcpy`s the
`0x2c40`-byte argument into its frame and enters the runtime
context exactly as wrapper a does; its own nested-runtime
panic site carries Location `node/src/utils.rs:66:79` (the
scheduler-side twin site carries `multi_thread/mod.rs:91:9`,
in both wrappers).

**Relationship.** The two bodies are the same idiom in two
different crates — build a runtime through the shared vendored
builder and block on it in place — but they are not the same
function and neither calls the other: different argument
shapes (`0x3d0` vs `0x2c40` bytes), different failure behaviour
(an `expect` with the message `tokio_run` in `base/src/lu.rs`
vs a plain `unwrap` in `node/src/utils.rs`), and opposite ends
of the call graph (a callback reached through a registration
table vs the callee of the process main).

## Census notes

The verifier recomputes a full reference census over `.text`
for both wrappers and their adapters: each wrapper has exactly
one rel32 caller (its adapter), no imm64 references, and a
single disp32 window that is the displacement field of that
same rel32 call. The builder slot `0x64e1760` has exactly three
call sites in `.text`: `0x15d7026`, `0x15d70c2` (wrapper a) and
`0x2ae16f2` (wrapper b). One disp32 window naming adapter b at
`0x2055ec8` lies inside the instruction at `0x2055ec6`
(`mov %r12,0xc8(%rsp)`) and is not an instruction start; the
only instruction-level reference to adapter b is the main
shim's `lea` (field at `0x2cef8fa`).

## Boundaries

- What the builder does with the cfg kind byte at `+0xe4`
  (stored by `cfg_ctor` from its argument; pinned here) and
  the `0x0101` pair at `+0xe5` is PR #2955 territory; this
  packet pins only who writes them.
- The builder body, `cfg_ctor` beyond its kind store, and the
  cfg drop bodies are PR #2950 boundaries, cited by span pins.
- The kind-1 arm's once consultation is pinned byte-wise;
  whether the guarded global caches the built runtime or
  serves another once-only purpose is not resolved by the
  traced window.
- Who registers the adapter-a callback in the static table at
  `0x6400548`, what list the dispatcher walks, and who calls
  the dispatcher are above the traced window.
- The `0x3d0`- and `0x2c40`-byte argument structs are pinned
  by size and by the adapters that build them; their field
  layouts are not traced.
- Wrapper b may itself be defined in `utils.rs` or inline a
  `utils.rs` helper into the entry body; the binary does not
  distinguish the two, and no function names are claimed for
  either wrapper.
