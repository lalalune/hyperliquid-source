# Tracked work item RE-005-node115-packet-cell-context

```text
program:   node #115 x86-64 node software
source:    artifacts/node/115/hl-node (byte-identical node captured
           by the enclosing repository)
technique: static identification of the one packet-cell field the
           layout packets (PR #3050, PR #3160) left open: the
           pointer at cell +0x10 ("context A"), over 19 pinned
           bodies -- the three families' spawn bodies (A
           0x15b80e0, X4 0x5cd9470, X5 0x5cf6e80), their sole
           callers (A 0x150b310, X4 0x5cd5ea0, X5 0x5cf5100),
           payload drops (A 0x5bc3bf0, X4 0x5cda210, X5
           0x5cfc3e0), cell glues (A 0x5bc2a80, X4 0x5cd86e0,
           X5 0x5ce8390), context-release glues (A 0x5bc24b0,
           X4 0x5cd88d0, X5 0x5ce8660), the shared scope panic
           stub (0x5c82d40), the standalone ScopeData
           decrement body (0x5c82d00) and the shared
           thread-field drop glue (0x5c98b40).  The context is the std
           scoped-thread scope state (ScopeData of
           library/std/src/thread/scoped.rs): a 0x28-byte Arc
           allocation -- strong count at +0x00, weak count at
           +0x08, the scope-creating thread's handle at +0x10,
           the running-thread counter at +0x18, a flag byte at
           +0x20.  The spawn-side counter increment overflows
           into the stub, which panics at the only scoped.rs
           Location record in the binary (0x64c32f0, line 60
           column 9) with "too many running threads in thread
           scope"; the payload drop's decrement tail sets the
           flag on a discarded live pair, decrements the
           counter and, at zero, xchgs 1 into the parker word
           at [A+0x10]+0x28 and futex-wakes it through the
           libc syscall slot iff it was parked (-1).  The
           release chain (cell glue strong decrement ->
           context-release glue: thread-handle drop, weak
           decrement, 0x28-byte dealloc) closes the Arc
           reading.  Producer side: the increment idiom occurs
           in exactly 14 spawn bodies binary-wide; their 16
           direct call sites all pass a null scope (last r9
           write is `xor %r9d,%r9d`, audited per site), and
           no indirect reference names any of the 14.  The
           three families' callers are unscoped spawns (the
           vendored threadpool crate, tokio's blocking pool,
           a std-functions/lazy_mutex spawn), so their packet
           cells always carry a null context.
execution: none
result:    records.json is generated from an authenticated ELF;
           the attempted check fails closed before any packet file
           is regenerated
```

## Files

- `records.json` — artifact identity, the 19 owner records (FDE
  extent, file offset, byte count, SHA-256), the per-instruction
  byte pins, the GOT slot resolutions (including the libc
  `syscall` GLOB_DAT behind the futex wake), the scoped.rs
  Location census (exactly one record), the panic message, the
  14-body spawn census, the audited 16-site call census, the
  indirect-reference census (all zero), the 6-body payload-drop
  census, the three callers' Location references, and the stated
  boundaries.
- `frames.txt` — the readelf frame lines for the 19 owners.
- `*.objdump.txt` — one disassembly export per owner body.

## Verification

```sh
python3 tools/packet_cell_context_static.py            # check mode
python3 tools/packet_cell_context_static.py --generate # regenerate
python3 -m unittest tests.test_packet_cell_context_static
```
