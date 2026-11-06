# Tracked work item RE-005-node115-x5-env-pair-source

```text
program:   node #115 x86-64 node software
source:    artifacts/node/115/hl-node (byte-identical node captured
           by the enclosing repository)
technique: static trace of the provenance of the X5 closure
           environment pair, the boundary the X4/X5 cell-layouts
           packet (PR #3160) left open: that packet pinned that the
           X5 spawn body (0x5cf6e80) copies the pair at closure
           +0x28/+0x30 out of a 0x20-byte caller argument struct,
           and that the dispatcher (0x5cf7710) stores the +0x30 word
           as the finished cell's vtable half, but not who builds
           the argument struct or what its words are.  Three bodies
           are pinned here: the sole caller of the spawn body
           (0x5cf5100, reached at the call site 0x5cf5347), and the
           dispatcher's two X5 adapters as consumers of the pair
           (adapter 2 at 0x5cdce30 via GOT slot 0x64ecb88, adapter 1
           at 0x5cdd010 via GOT slot 0x64ecb98, a 34-byte shim that
           forwards a copy of the whole closure).  A full .text
           rel32 scan plus relocation and writable-segment scans
           show the spawn body has exactly one caller and no stored
           or relocated copy of its address; the caller body in
           turn has no direct callers, and one RELATIVE relocation
           (slot 0x64e7718) stores its address in a writable static
           table.  Inside the caller, the argument struct (stack
           base rsp+0x20, passed as the spawn body's stack argument)
           is built as follows.  The +0x00 word (closure +0x28, the
           pair's data half) is a boolean: 1 if the first word of
           the caller's own fourth-argument struct equals 1, else 0
           (compare at 0x5cf52ef, set at 0x5cf52dd, clear at
           0x5cf5308, store at 0x5cf530b).  The +0x08 word (closure
           +0x30, the half the dispatcher stores as the cell vtable)
           is the second word of the same fourth-argument struct
           (loaded at 0x5cf528a), a pointer whose first qword the
           caller increments with a locked xadd before the call
           (0x5cf52e9) -- the strong-count clone of a
           reference-counted allocation, not a static vtable
           address; no static address is loaded into either pair
           word.  The remaining two words are read out of the
           caller's state struct: +0x10 (closure +0x38) is the
           reference-counted pointer at state +0x98 (incremented
           with a locked inc at 0x5cf5269), and +0x18 (closure
           +0x40) is the plain word at state +0xb8.  The second
           adapter confirms the typing from the consumer side: it
           reads the pair's first word as a byte boolean (0x5cdcee3,
           inverted at 0x5cdceea, shifted by 6 at 0x5cdceef) and
           dereferences the pointer pair at +0x1f8 of the struct
           the second word points to (0x5cdcef2), passing the
           selected entry +0x10 on with the closure +0x40 word,
           and decrements the count of the closure +0x38 pointer
           (0x5cdcf13).  So for X5 the finished cell's +0x28 word
           holds a per-instance heap pointer to a reference-counted
           struct, in contrast to X4, whose cell +0x28 holds the
           static table base 0x64c5330 (PR #3160).  Not pinned:
           the concrete type names of the reference-counted struct,
           of the fourth-argument struct and of the state struct
           (no symbol or string in the binary names them; their
           shapes are pinned instead), which consumer loads the
           caller slot 0x64e7718, where the state fields +0x98 and
           +0xb8 themselves originate, and any run-time choice
           between the two bool-indexed entries.
execution: none
result:    records.json is generated from an authenticated ELF;
           the attempted check fails closed before any packet file
           is regenerated
```

## Files

- `records.json` — artifact identity, the 3 owner records (FDE
  extent, file offset, byte count, SHA-256), the per-instruction
  byte pins for the caller and the second adapter, the static slot
  resolutions, the reference audit for the spawn body and its
  caller (direct branches, relocation slots, stored copies), the
  pair provenance answer, and the stated boundaries.
- `frames.txt` — the readelf frame lines for the 3 owners.
- `*.objdump.txt` — one disassembly export per owner body.
- `MANIFEST.sha256` — SHA-256 of every other file in this
  directory.
