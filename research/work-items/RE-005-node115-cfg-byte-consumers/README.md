# RE-005 node115 cfg byte consumers: the +0xa/+0xb bytes nobody reads

Status: static evidence packet for one bounded RE-005 question. The
companion verifier is `tools/cfg_byte_consumers_static.py`; retained
exports sit beside this file and are hash-bound by `MANIFEST.sha256`.

## Question

The tag-3 supply packet (#2950) closed with an open edge, in its own
words: "cfg+0xa/+0xb are assembled but never read by the ctor." The
runtime builder `0x5cf9600` assembles a 16-byte config on its own
stack and hands it to `driver_ctor` `0x5ce01f0` at two call sites.
Who reads the bytes at +0xa/+0xb of that config, what branch do they
drive, and is the set of values they can take closed by the wrapper
fixed values?

## Result

Nobody reads them, and they decide nothing. Both bytes are dead on
every path the artifact can build, and their reachable values are
closed:

- The builder receives the runtime config built by `cfg_ctor`
  `0x5cf93f0` (bcfg) and assembles the ctor config (dcfg) at
  `rsp+0x70` (ctor call site 1, `0x5cf9669`) and `rsp+0x730` (ctor
  call site 2, `0x5cf96eb`):
  - `dcfg+0x00` qword = `[bcfg+0x60]`
  - `dcfg+0x08` byte = `[bcfg+0xe5]` (variant), `dcfg+0x09` byte =
    `[bcfg+0xe6]` (tag) — the u16 the wrappers fix to `0x0101`
  - `dcfg+0x0a` byte = immediate `1` at site 1; `[bcfg+0xe4] ^ 1`
    at site 2
  - `dcfg+0x0b` byte = `[bcfg+0xe7]`
  Exactly four stores land in each dcfg extent before its call;
  there are no other writers.
- `driver_ctor` reads exactly three dcfg fields: the `+0x00` qword
  (`0x5ce0211`, forwarded as `Poll::new` `0x5ceeae0`'s second
  argument), the `+0x08` byte (`0x5ce0207`, its entry variant
  branch) and the `+0x09` byte (`0x5ce03f6`, compared against 1 in
  the install sequence — the flag #2948 showed selecting the time
  context's base pair). No access at any width in the ctor covers
  +0xa or +0xb, and the dcfg pointer never escapes: it is not
  passed to any callee and not stored anywhere in the ctor.
- Reachable values are closed by the wrappers. `[bcfg+0xe4]` is
  `cfg_ctor`'s second argument, fixed to 1, 0, 1 at the three
  wrapper call sites (wrapper A `0x15d7007` / `0x15d70a3`, wrapper
  B `0x2ae16d1`), and ctor call site 2 is entered only when it is
  1, so `dcfg+0x0a` is 1 at site 1 and 0 at site 2 — uniformly
  `NOT [bcfg+0xe4]`. `[bcfg+0xe7]` is 0: `cfg_ctor` stores a zero
  dword at `+0xe5` (covering `+0xe7`) and the wrapper overwrite is
  a two-byte store at `+0xe5..+0xe6` only, so `dcfg+0x0b` is 0 at
  both sites.
- The received config's own +0xa/+0xb bytes (inside the qword slot
  `[bcfg+0x8]`) have exactly one covering access in the artifact:
  the builder's fast-path qword load at `0x5cf962d`, gated on
  `[bcfg+0xe4] == 1` and `[bcfg+0x0] == 1`. `cfg_ctor` never writes
  the `+0x8` slot and always writes `[bcfg+0x0] = 0`, so that arm —
  the one #2950 recorded as not supplied by the artifact's own
  config constructor — is unreachable for every config the
  artifact builds, and the two bytes are never even loaded. The
  remaining bcfg consumers make no covering access either: the
  pair helper `0x5cf3d00` (called by the builder with bcfg at
  `0x5cf9798` / `0x5cf99f3`) and the cfg drop body `0x5cf1af0`
  (called by wrapper A at `0x15d7034`). After the drop call the
  wrappers reuse the bcfg stack slot for unrelated values; those
  later stores are recorded in the census separately and cannot
  reach the build.

## Method

Eight bodies are extent- and digest-pinned (six of them
cross-checked against the digests #2950 published). The packet
re-derives: the complete cfg-access census of `driver_ctor`
(three accesses), the complete bcfg-access census of the builder
up to the instruction where `r14` stops holding bcfg
(`0x5cf9bc6`), the complete `cfg_ctor` store census (23 stores),
the complete access censuses of the pair helper and the cfg drop
body, the rsp-relative censuses of both wrappers over the bcfg
extent, and instruction pins for every cfg-relevant store, load,
compare and call on the path. All of it is re-derived from the
authenticated #115 artifact by
`tools/cfg_byte_consumers_static.py` and pinned by
`tests/test_cfg_byte_consumers_static.py`.

## Open edges

- The two wrapper bodies' source-level identity remains unpinned
  (inherited from #2950); this packet pins their cfg-relevant
  instructions only.
- What `[bcfg+0xe4]` means at source level (the `cfg_ctor`
  argument the wrappers fix to 1/0/1) is not identified; the
  packet pins its flow into `dcfg+0x0a` and the builder entry
  compare only.
- The builder's `[bcfg+0x0] == 1` arm takes a config built
  outside this artifact; who writes such a config, and the
  `[bcfg+0x8]` qword it forwards to the post-build path, is
  outside the artifact and not claimed.
- `builder_precall` `0x5cf5db0` is pinned by extent and digest
  (cross-checked against #2950) and as the fast path's replaced
  value supplier; its source-level identity is not re-derived
  here.
