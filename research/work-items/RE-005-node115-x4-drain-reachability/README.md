# Tracked work item RE-005-node115-x4-drain-reachability

```text
program:   node #115 x86-64 node software
source:    artifacts/node/115/hl-node (byte-identical node captured
           by the enclosing repository)
technique: static reachability trace of the X4 packet cell's
           standalone drain helper (0x5cd8580, pinned by the
           X4/X5 cell-layout packet #3160, which left its
           reachability open), over seven pinned bodies: the
           X4 drain helper itself, the X4 cell drop glue
           (0x5cd86e0), the X4 payload drop (0x5cda210), the
           FDE immediately preceding the helper (0x5cd8540),
           and the X5 control triple (drain 0x5ce7d70, cell
           glue 0x5ce8390, payload drop 0x5cfc3e0).  A census
           of every static reference channel (direct rel32
           branches, 64-bit pointer occurrences, 32-bit
           immediates, relocation addends, rip-relative
           address computations, fall-through) finds exactly
           one reference to the helper: the direct call at
           0x5cd87df.  That call sits in the cell glue's
           landing pad at 0x5cd87c1, which the glue's LSDA
           call-site table assigns to exactly one call site,
           the payload-drop call at 0x5cd86f2; the glue's
           main path drains inline (state test at 0x5cd870e)
           and never calls the helper.  The payload drop can
           unwind out of its frame only from its pair drop
           call (assigned its own pad 0x5cda2db, action 5),
           from that pad's rethrow processing, or from its
           context-ledger panic tail jump -- and on every
           one of those paths the state word at cell +0x18
           has already been stored 0 (normal path 0x5cda276,
           payload pad 0x5cda30a) before the glue pad runs,
           so the helper's guard reads zero and it drops
           nothing.  The helper is landing-pad cleanup for
           a panicking payload drop and never drains a live
           pair; the live drains are the inlined copies in
           the dispatcher, the payload drop and the glue's
           main path.  The X5 control is geometrically
           identical (sole call at 0x5ce8494 in the glue pad
           0x5ce8476, payload pad state store at 0x5cfc4da).
           The one boundary: the payload drop's two dealloc
           calls have no LSDA call-site entry (recorded
           non-unwinding); a hypothetical unwind there is
           the only path that could enter the pad with the
           state word still 1, with the pair's allocation
           already being freed by that call.
execution: none
result:    records.json is generated from an authenticated ELF;
           the attempted check fails closed before any packet file
           is regenerated
```

## Files

- `records.json` — artifact identity, the seven owner records
  (FDE extent, file offset, byte count, SHA-256), the
  per-instruction byte pins, the GOT slot resolutions, the
  reference census, the LSDA call-site tables of both
  families' drain/glue/payload-drop bodies, the unwind-path
  audit, and the stated boundaries.
- `frames.txt` — the readelf frame lines for the seven owners.
- `*.objdump.txt` — one disassembly export per owner body.
