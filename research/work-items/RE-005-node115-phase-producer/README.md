# Tracked work item RE-005-node115-phase-producer

```text
program:   node #115 x86-64 node software
source:    artifacts/node/115/hl-node (byte-identical node captured
           by the enclosing repository)
technique: static trace of the two questions the spawn-payload
           packet (PR #2582) left open, over ten pinned bodies:
           lvl4_c (0x2ae1690), its two shaper callees lvl4_a
           (0x2ae41e0) and lvl3_c (0x2cde430), ctor_c (0x2cd8370),
           the registrar stub (0x2cef8f0, the binary's main) and
           the registrar body (0x5c99970, GOT slot 0x64e6c30), the
           record builder (0x2b7b640), the b-side chain pre_4ab
           (0x24535c0) and call4a_b (0x2b404b0), and the phase
           fill callee (0x5cf9600) as context.  lvl4_c's frame
           packs four 0x2c40-byte phase-sized regions, and on
           both arms that reach a shaper lvl4_c memcpy's the
           whole entry phase struct (ctor_c's frame, saved at
           [rsp+0x18]) into its buffer at [rsp+0x5aa8] through
           the memcpy slot 0x64df508 -- at 0x2ae19cc before the
           direct lvl4_a call and at 0x2ae1b1f before the
           lvl3_c/pre_4ab arm -- overwriting the slot-1760 fill
           of [0x0..0x50) in full.  A complete frame census
           finds exactly four direct stores into the buffer
           region, all at +0x0/+0x8 and all overwritten by the
           copies.  ctor_c itself writes only three phase
           offsets (stack probes at +0xc40 and +0x1c40, and the
           dispatch byte +0x21a = 0); above it there is no
           static writer or caller -- its address is taken once
           by main and registered with the registrar body under
           the key cell 0x6440b48, whose only references are
           the stub's.  On the dispatch arm the zeroed byte
           selects, each shaper rebuilds the shaping sources
           +0xc8..+0xf0 and the +0x1e8 byte from its own stack
           record (lvl3_c via the builder's 0x98-byte record,
           keyed by the .rodata string "hl-node"); on every
           other arm those fields are the incoming memcpy'd
           bytes, i.e. residue above the registrar boundary.
           The b-side [[rdx]] chain resolves statically to
           the same buffer: lvl4_c's descriptor at [rsp+0x60],
           pre_4ab's cell at [rsp+0x48], call4a_b's rdi =
           [rbp+0] at 0x2b40573.
execution: none
result:    records.json is generated from an authenticated ELF;
           the attempted check fails closed before any packet file
           is regenerated
```

## Files

- `records.json` — artifact identity, the ten owner records (FDE
  extent, file offset, byte count, SHA-256), the per-instruction
  byte pins for the six exported bodies (and the load-bearing
  instructions of the four hash-only bodies), the GOT-slot census
  (the registrar and fill slots' relocations and complete
  rip-relative reference lists, the memcpy slot's GLOB_DAT
  relocation, symbol and in-lvl4_c call sites, the config slot's
  relocation), the key-cell census, the direct-call-site census
  of the seven traced bodies (with tail-call and lea census), the
  lvl4_c frame census (every classified access in the two
  phase-sized regions and the saved-entry-pointer uses), the
  small-body censuses of ctor_c and the stub, the classified
  access censuses of the two shapers (stores, loads and
  address-takens by phase register and offset, with store
  sites), the phase-producer, field-attribution and b-side
  findings records, the boundaries and the method limits.
- `*.objdump.txt` — full objdump exports of the six bodies of at
  most about 4 KB (ctor_c, the registrar stub, the registrar
  body, the builder, pre_4ab, call4a_b). Path normalised to
  `<authenticated-node115>`; regenerate to compare.
- `frames.txt` — the `readelf -wf` lines for the ten owner
  functions.
- `MANIFEST.sha256` — hashes for every packet file.

## Regeneration

Run from the repository root with the artifact materialised:

### Regenerate the packet files

```sh
python3 tools/phase_producer_static.py --generate
```

### Verify the manifest

```sh
(cd research/work-items/RE-005-node115-phase-producer && \
 sha256sum -c MANIFEST.sha256)
```

### Run the dedicated tests

```sh
python3 -m unittest tests.test_phase_producer_static -v
```

## Static boundary

No captured instruction was executed.  The classified censuses
classify each instruction by operand position in fresh objdump
text; register identity follows the entry assignments (rbx = rdi
in lvl4_a, r13 = [[rdi+8]] in lvl3_c, each set once), and lvl4_c's
rsp does not move between its prologue and epilogue, so its frame
offsets are absolute for the whole body.  Whole-struct copies
move bytes without naming fields — the five lvl4_c memcpys and
lvl3_c's 0x98-byte rebuild copy are enumerated as call sites with
pinned argument setups — so for copied fields the census is a
statement about direct accesses and the copies actually observed.
Arm attribution follows the entry dispatch structure read from
the disassembly; jump-table reachability beyond that structure
is not re-decided here.  Who invokes ctor_c at runtime is not
established: its pointer sits in the registrar's runtime state
after main registers it, and no static reference exposes the
invocation.
