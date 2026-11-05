# RE-005 node 115: who writes to the signal state's sv[1] word at run time

Packet type: static evidence (target-bound). Continues
RE-005-node115-signal-fd-producer (PR #2952), whose open edge 1
asked: the 32-byte global signal state at 0x64fee20 stores a
socketpair as +0x00 sv[1] / +0x04 sv[0]; no .text body loads the
+0x00 word through an absolute reference, so who writes to sv[1]
(the wake end) at run time?

## Question

Starting from the #2952 pins (global layout, the single absolute
reader of sv[0], the init closure that creates the pair), trace
every path by which the +0x00 word's value can be used after
publication: bodies that receive the whole state (or its address)
as an argument, copies of the get_or_init result, and the write
side of the wake path. If the writer is reachable only indirectly,
name the exact indirect path; if some part is statically
unreachable, pin the absence by census.

## Answer

**The only run-time writer to sv[1] is the registered per-signal
action of the vendored signal machinery — one closure type with
two call shims, wake_call 0x5cdcda0 (135 B) and wake_call_once
0x5cdd040 (135 B).** It never references the global by address.
It receives a closure environment `{&state, signal}` and loads
the fd through that pointer: `mov (%rcx),%edi` (byte pin `8b39`
in both shims), then calls libc `send` (GOT 0x64eb088, GLOB_DAT)
with length 1, buffer = the constant byte 0x01 at 0x94c786, and
flags 0x4000 (`MSG_DONTWAIT`). Before sending, it sets the
per-signal pending flag — `xchg` of byte 1 into
`entries[signal-1] + 8` — the same flag byte the drain body
0x5ce7380 exchanges back to 0 on the read side (#2952).

The full chain, every link pinned in records.json:

1. **Registration.** entry_lookup 0x5cde710 (per-signal
   OnceLock) reaches the entry-init closure entry_init
   0x5cdbf20 through the OnceLock shim 0x5cdf535 and the two
   closure shims 0x5cdf460 / 0x5cdf630 (the only two E8 callers
   of entry_init). entry_init allocates a 0x20-byte Arc
   environment — counts 1/1 at +0/+8, the state address
   0x64fee20 stored at +0x10, the signal number at +0x18
   (byte pin at 0x5cdbf92) — and hands it to registry_insert
   0x5cdd480 (call pin at 0x5cdc14b).
2. **Trait-object formation.** registry_insert attaches the
   wake vtable 0x64c54b8 to the environment. The vtable's slots:
   +0x08 size 0x10, +0x10 align 8, +0x18 (call_once) →
   wake_call_once 0x5cdd040, +0x20 → wake_call 0x5cdcda0,
   +0x28 → wake_call 0x5cdcda0. All five verified .text
   references to the vtable are lea sites inside
   registry_insert; the wake bodies have no E8 callers and no
   other references anywhere in the artifact.
3. **Handler installation.** On the first registration for a
   signal, entry_init queries the current sigaction
   (call pin 0x5cdc418), preserves the previous handler inside
   a 0xa8-byte registry record, and installs the raw handler
   os_handler 0x5c67560 (lea pin 0x5cdc655, stored to the new
   act's handler field at 0x5cdc65c; flags word 0x10000004 =
   SA_SIGINFO | SA_RESTORER) via a second sigaction call
   (pin 0x5cdc6e2, GOT 0x64ec510 = sigaction).
4. **Invocation.** On signal delivery, os_handler walks the
   registry's per-signal action list, loads each action's
   (environment, vtable) pair, and invokes it with
   `call *0x28(%rax)` (byte pin `ff5028` at 0x5c67834) — the
   vtable slot that resolves to wake_call. A send error is
   converted to an io error value by io_error_ctor 0x5cdd280
   and discarded by the handler.
5. **Read side (for contrast, #2952).** signal_attach loads
   sv[0] — the only absolute load of either fd word — dups it
   with fcntl F_DUPFD_CLOEXEC and registers the dup with
   epoll_ctl; table_drain recv's on that dup. sv[1] is
   write-only and has exactly one writer.

## Boundary pins (what this packet does *not* claim)

- The whole-.text absolute census is re-run here, not inherited:
  verified RIP-relative sites against the global are six lea
  (all of the base address, in entry_lookup / signal_attach /
  table_drain), one load at +0x04, two at +0x08, three at +0x10,
  four at the +0x18 Once word — and no load or store of +0x00
  in any encoding; imm64 occurrences of every address in
  [0x64fee20, 0x64fee38) inside .text: 0.
- The word at 0x64fee18, eight bytes below the global, is a
  different static: eight verified `lock xadd` sites target it
  (e.g. 0x5ce20d2). It is not part of the signal state and is
  not a back-door reference to sv[1].
- A generic send helper 0x5cdfc90 also calls the send GOT slot
  (the third of exactly three FF 15 send sites). It sends on an
  fd stored inside its own argument object (+0x18) and has 13
  E8 callers, none in the signal cluster; it never touches the
  signal global.
- At init time, and only then, the +0x00 word is stored once by
  the Once shim's bulk store of the socketpair result (#2952).
  This packet's claim covers run-time use after publication.
- The vtable's +0x00 slot reads 0 in the file image (no
  relocation); the drop slot's runtime value is not claimed.

## Open gaps

1. Source-level names for entry_init / registry_insert /
   os_handler inside the vendored signal-hook-registry-style
   code are inferred from behaviour (sigaction chaining,
   per-signal action lists, half-lock records); no debug info
   exists to confirm them.
2. Whether os_handler ever invokes the +0x20 slot
   (call_mut) for this closure is not decided — the observed
   dispatch uses +0x28 only; both slots resolve to the same
   body, so the writer's identity does not depend on it.
3. The wake byte's value (0x01) is content-free for the drain
   side, which discards the received bytes; no claim is made
   about why 0x01 was chosen.

## Evidence

- `records.json` — artifact hash, 17 FDE-bounded body SHA-256
  pins (five cross-checked byte-identical against #2952's
  independently produced pins: entry_lookup, signal_attach,
  table_drain, init_closure, entry_arc_clone), the global's
  born bytes, the full absolute/imm64/E8/FF-15 censuses, GOT
  resolutions, the wake vtable, and 11 instruction byte pins.
- `tools/signal_sv1_writer_static.py` re-derives every record
  from the artifact alone and prints `{"matches": true}`
  against the checked-in records.
- `tests/test_signal_sv1_writer_static.py` — 8 tests, all
  passing with the artifact materialised (0 skipped).
- Objdump excerpts: both wake shims in full, os_handler,
  entry_lookup, signal_attach, table_drain, oncelock_shim,
  entry_init head (environment allocation) and sigaction
  regions, registry_insert head (vtable attachment).
