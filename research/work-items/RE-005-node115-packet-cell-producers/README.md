# Tracked work item RE-005-node115-packet-cell-producers

```text
program:   node #115 x86-64 node software
source:    artifacts/node/115/hl-node (byte-identical node captured
           by the enclosing repository)
technique: static trace of the two ends the dispatcher-table
           packet (PR #3000) left open, over 24 pinned bodies: the
           four dispatchers of static-table family L (entries
           0x64004d0..0x6400530), seven sibling dispatchers of four
           further families, the v4 spawn body (0x15b80e0) and join
           body (0x15b8810), the thread start routine (0x5ca44a0)
           and thread create body (0x5c87b50), the v4 closure drop
           (0x15bb300), the cell Arc drop glue (0x5bc2a80) and cell
           payload drop (0x5bc3bf0), the catch-pair helper
           (0x5bb19f0), begin_catch (0x1680cab), the dealloc body
           (0x635de30) and the two v4 adapters.  The packet cell is
           the 0x30-byte Arc allocation whose pointer sits at
           closure +0x20: strong count at +0x00, weak count at
           +0x08, context pointer at +0x10, state at +0x18, data at
           +0x20, vtable at +0x28.  The completion-store idiom --
           movq $1,[base+0x18]; mov %r14,[base+0x20];
           mov %r15,[base+0x28] -- occurs in exactly 13 bodies in
           .text: the 11 dispatchers (base rbp) and two stack-value
           constructions (base rsp) that never touch a heap cell.
           The only body that stores the pair into the v4 cell
           instance is the dispatcher 0x15b8fd0 itself, on its
           single finish block (fall-through copy at
           0x15b90da..0x15b90e6, landing-pad copy at
           0x15b9141..0x15b914d).  On the normal path r14 is zeroed
           at entry (0x15b9083), so the cell is left holding
           {data = NULL, vtable = r15}; on the catch path the pair
           is the panic payload's Box fat pointer, extracted by
           the helper behind GOT slot 0x64dfe88 from the caught
           panic object (magic "MOZ\0RUST" at +0x00, box data at
           +0x28, box vtable at +0x30, returned in rax:rdx and
           moved to r14:r15 at 0x15b918b/0x15b918e).  The r15 value
           stored back on the normal path is pinned from the
           producer side: the dispatcher writes r15 only on the
           catch path (0x15b918e); its sole caller, the thread
           start routine, loads r15 from package +0x10 at
           0x5ca45a6 and holds it across the call *0x18(%r15) at
           0x5ca45d7; and package +0x10 is written by the spawn
           body, which stores the lea of its own static-table
           entry base 0x6400530 (lea at 0x15b8436) there.  The
           vtable half stored back is therefore the dispatcher's
           own entry vtable base.  The cell's remaining writers
           are its spawn body (initialisation: state 0, pair slot
           uninitialised), the join body (take: pair loaded out,
           state := 0) and the two drop paths (drain-if-present).
execution: none
result:    records.json is generated from an authenticated ELF;
           the attempted check fails closed before any packet file
           is regenerated
```

## Files

- `records.json` — artifact identity, the 24 owner records (FDE
  extent, file offset, byte count, SHA-256), the per-instruction
  byte pins, the 11 static-table entries (drop, size, align,
  method, all from RELATIVE relocations), the 11 GOT slots'
  relocation targets, the completion-store idiom census (13
  bodies, each verified against the FDE-synced disassembly of
  its containing body), the lea census of the 11 table entries
  (exactly one lea per entry, inside its own spawn body), the
  direct-call census (the v4 dispatcher and the thread start
  routine have no direct callers; the spawn body has exactly
  one, at 0x150b98c), the r15 audit of the v4 dispatcher (one
  r15 write, on the catch path only), the v4 dispatcher store
  audit, the findings records, the boundaries and the method
  limits.
- `*.objdump.txt` — full objdump exports of the ten bodies of at
  most about 8 KB (dispatcher_v4, dispatcher_v3, spawn_v4,
  join_v4, closure_drop_v4, cell_arc_drop, cell_payload_drop,
  catch_pair, thread_start, adapter_a_v4). Path normalised to
  `<authenticated-node115>`; regenerate to compare.
- `frames.txt` — the `readelf -wf` lines for the 24 owner
  functions.
- `MANIFEST.sha256` — hashes for every packet file.

## Regeneration

Run from the repository root with the artifact materialised:

### Regenerate the packet files

```sh
python3 tools/packet_cell_producers_static.py --generate
```

### Verify the manifest

```sh
(cd research/work-items/RE-005-node115-packet-cell-producers && \
 sha256sum -c MANIFEST.sha256)
```

### Run the dedicated tests

```sh
python3 -m unittest tests.test_packet_cell_producers_static -v
```

## Static boundary

No captured instruction was executed.  The idiom census scans
.text for the byte encodings of the three completion stores
(including the SIB forms used with an rsp base) and verifies
every candidate body against its FDE-synced disassembly: a body
counts only when all three stores appear on one base register.
Byte-pattern hits that do not survive that check are not
counted.  What the context object at cell +0x10 is at source
level is not pinned: the binary shows a refcounted object (Arc
count at +0x00, second atomic counter at +0x18, flag byte at
+0x20) handed to each spawn body as an argument and stored into
the fresh cell; no string or Location names it on these paths.
The sibling dispatchers drain cells of the same or further cell
types for their own closures; who owns those JoinHandles and
whether their callers ever read the returned pair is not traced
here.
