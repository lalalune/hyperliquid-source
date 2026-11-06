# Tracked work item RE-005-node115-x4-x5-cell-layouts

```text
program:   node #115 x86-64 node software
source:    artifacts/node/115/hl-node (byte-identical node captured
           by the enclosing repository)
technique: static trace of the two packet cell layouts the
           producers packet (PR #3050) left unpinned, over 14
           pinned bodies: the X4 spawn body (0x5cd9470) and
           dispatcher (0x5cd9b30, entry 0x64c5330), the X4 cell
           drop glue (0x5cd86e0), payload drop (0x5cda210),
           drain helper (0x5cd8580) and context release glue
           (0x5cd88d0); the X5 spawn body (0x5cf6e80),
           dispatcher (0x5cf7710, entry 0x64c6ac0), join body
           (0x5cf7550), cell drop glue (0x5ce8390), payload
           drop (0x5cfc3e0), drain helper (0x5ce7d70) and
           context release glue (0x5ce8660); and the thread
           start routine (0x5ca44a0) cross-pinned from #3050.
           Both cells are 0x30-byte, align-8 Arc allocations
           at closure +0x20 with the type-A field offsets:
           strong count at +0x00, weak count at +0x08,
           context pointer at +0x10, state at +0x18, data at
           +0x20, vtable at +0x28.  The spawn bodies write the
           counts (1/1) and the context pointer (from argument
           r9, incrementing the counter at A+0x18) and zero
           the state, leaving the pair slot uninitialised;
           only the dispatcher finish blocks (two copies
           each) write state 1 and the pair.  On the normal
           path data is 0 in both families; the vtable half
           is the entry base 0x64c5330 (in r15 from the thread
           start routine) for X4, but the word at closure
           +0x30 -- the vtable half of a fat-pointer field of
           the X5 closure environment -- for X5.  On the catch
           path both store the panic Box pair from the shared
           catch-pair helper (GOT slot 0x64dfe88).  Consumers:
           the dispatchers drain a live pair before storing;
           the payload drops drain, zero the state and do the
           context bookkeeping (flag at A+0x20, counter at
           A+0x18, xchg at [A+0x10]+0x28); the cell glues
           release the context pointer through the family
           slot (X4 0x64ecb68, X5 0x64ecc50), decrement the
           weak count and deallocate 0x30 bytes; the X5 join
           body takes the pair out (offsets pinned here; its
           take/release semantics are open PR #3074's
           subject).  No body takes the X4 pair out.
execution: none
result:    records.json is generated from an authenticated ELF;
           the attempted check fails closed before any packet file
           is regenerated
```

## Files

- `records.json` — artifact identity, the 14 owner records (FDE
  extent, file offset, byte count, SHA-256), the per-instruction
  byte pins, the two static-table entries, the GOT slot
  resolutions, the finish-store audit for both dispatchers, and
  the stated boundaries.
- `frames.txt` — the readelf frame lines for the 14 owners.
- `*.objdump.txt` — one disassembly export per owner body.
- `MANIFEST.sha256` — SHA-256 of every other file in this
  directory.
