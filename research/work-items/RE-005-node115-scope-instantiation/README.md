# Tracked work item RE-005-node115-scope-instantiation

```text
program:   node #115 x86-64 node software
source:    artifacts/node/115/hl-node (byte-identical node captured
           by the enclosing repository)
technique: four closed censuses over the authenticated ELF --
           strings, panic Locations (through the .rela.dyn
           relocation addends that carry their file pointers),
           direct and rip-relative code references, and data
           pointers -- answering the one question the packet-cell
           context packet (PR #3204) left open as a boundary:
           whether std::thread::scope is instantiated anywhere
           in the binary.  That packet pinned the packet cells'
           context pointer as std's ScopeData
           (library/std/src/thread/scoped.rs), showed the spawn
           bodies' counter increment overflowing through the
           shared stub 0x5c82d40 into the artifact's only
           scoped.rs panic Location (0x64c32f0, line 60 col 9,
           "too many running threads in thread scope"), and
           showed all 16 call sites of all 14 spawn
           monomorphisations passing a null context -- but a
           Scope::spawn instantiation that built its packet
           without going through those spawn bodies would have
           evaded the call-site census.  The censuses here close
           every artefact such an instantiation would leave:
           (1) the scope-exit panic string "a scoped thread
           panicked", which every thread::scope monomorphisation
           carries on the data-dependent a_thread_panicked
           branch, occurs nowhere in the 105,896,032 bytes, and
           the substring "scoped" occurs exactly once, inside
           the scoped.rs path string itself; (2) exactly one
           panic Location names scoped.rs -- the overflow one --
           with none for the scope-exit panic and none for
           Scope::spawn's expect, although the same relocation
           scan recovers 1,209 std .rs Locations in total;
           (3) the overflow stub is called directly from
           exactly 14 sites, site-for-site the stub_call_site
           list of PR #3204's spawn census, each inside one of
           the 14 pinned spawn bodies, and the stub's address
           occurs nowhere as data (no literal outside the
           relocation tables, no relocation addend), so it has
           no indirect entry; an own-increment Scope::spawn
           would still have to reach a panic through this stub
           or through its own reference to the Location, and
           the Location's only code reference in the artifact
           is the stub's lea at 0x5c82d53; (4) the standalone
           ScopeData::decrement body 0x5c82d00 has no direct
           caller, its address is named by exactly one
           relocation slot (0x64ec708), and the only call
           through that slot is the overflow stub's rollback
           at 0x5c82d46 with the panic-flag argument zeroed.
           Conclusion: thread::scope is not instantiated in
           this artifact and ScopeData is never constructed;
           the surviving scope machinery is exactly {the
           overflow stub, the decrement body it rolls back
           through, and the counter ledger inlined in the
           spawn bodies and payload drops}, reachable only
           with the null context every spawn call site passes.
execution: none
result:    records.json is generated from an authenticated ELF;
           the attempted check fails closed before any packet file
           is regenerated
```

## Files

- `records.json` — artifact identity, the two owner records (FDE
  extent, file offset, byte count, SHA-256), the per-instruction
  byte pins for both bodies, the GOT-slot relocation records,
  and the four censuses: the string census, the scoped.rs
  Location census, the overflow stub's direct-xref census, the
  reference census (Location/message code references, the
  decrement's callers and slots) and the data-pointer census.
- `scope_overflow_stub.objdump.txt` — disassembly of the
  overflow stub 0x5c82d40..0x5c82d65: the rollback call through
  the decrement slot, the two lea's (panic message, panic
  Location) and the call through the panic slot.
- `scope_decrement.objdump.txt` — disassembly of the standalone
  decrement body 0x5c82d00..0x5c82d3b: flag store gated on the
  boolean argument, the locked decrement, and the unpark tail
  (parker-word xchg, futex wake through the libc syscall slot).
- `frames.txt` — the .eh_frame FDE lines of the two owner
  bodies.
- `MANIFEST.sha256` — SHA-256 of every other file in this
  directory.
