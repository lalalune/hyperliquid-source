# Tracked work item RE-005-node115-config-fetch

```text
program:   node #115 x86-64 node software
source:    artifacts/node/115/hl-node (byte-identical node captured
           by the enclosing repository)
technique: static trace of the question the phase-producer packet
           (PR #2589) left open as its first edge, over ten pinned
           bodies: the config callee (0x1506840, GOT slot
           0x64e0a80), its predicate (0x14c2a40), the record
           builder (0x2b7b640), the lookup chain lookup_a
           (0x163a4b0), lookup_b (0x564d700), lookup_c (0x165de90)
           with its worker (0x165dfb0), lookup_d (0x564cce0), and
           the two shapers lvl4_a (0x2ae41e0) and lvl3_c
           (0x2cde430) as call-site context.  The "config fetch"
           is not a fetch: the callee never stores through its
           argument pointer (a complete bracket census finds
           eight loads through rdi and no store, lea or
           other-destination access), returns nothing any of
           its four callers consumes, and only reads a staged
           copy of the caller's seeded 0x50-byte struct to
           decide whether to log "enable_log not applied"
           against "base/src/log/state.rs".  Its complete
           rip-relative reference list is four FF 15 call
           sites (lvl4_a, lvl3_c and two further bodies); no
           instruction calls the callee directly, and
           builder_c contains no reference to the slot at
           all.  The 0x98-byte rebuild record is therefore
           attributed without it: on the tagged arm builder_c
           writes +0x0 = 0x10 and copies the converted
           value's +0x8..+0x40, leaving +0x40..+0x98 to the
           record buffer; on the other arm lookup_d rewrites
           the default entry lookup_a built from the "hl-node"
           key descriptor -- +0x0..+0x78 from the value built
           out of the converted value's +0x48 sub-object,
           +0x78/+0x88 the "key" field's length, +0x80 a fresh
           copy of its bytes, the +0x90 byte the "chain"
           field's tag (Local 0, Sandbox 1, Testnet 2,
           Mainnet 3) -- over lookup_a's zeroed +0x90 qword.
execution: none
result:    records.json is generated from an authenticated ELF;
           the attempted check fails closed before any packet file
           is regenerated
```

## Files

- `records.json` — artifact identity, the ten owner records (FDE
  extent, file offset, byte count, SHA-256), the per-instruction
  byte pins for the eight exported bodies plus absolute site pins
  for the two further config-slot callers' seed stores, the
  GOT-slot census (eighteen R_X86_64_RELATIVE slots on the traced
  paths and the memcpy slot's GLOB_DAT relocation and symbol),
  the config slot's complete rip-relative reference census (with
  the empty direct-call census for its callee), the bracket
  censuses of the config callee, the predicate, lookup_a and
  lookup_d, the in-body rip-target and direct-call maps of the
  five small bodies, the string and global records (every string
  re-read through the section table), and the config-fetch,
  predicate, record-attribution findings records, the boundaries
  and the method limits.
- `*.objdump.txt` — full objdump exports of the eight bodies of
  at most about 4 KB (the config callee, the predicate, the
  builder, lookup_a, lookup_b, lookup_c, its worker, lookup_d).
  Path normalised to `<authenticated-node115>`; regenerate to
  compare.
- `frames.txt` — the `readelf -wf` lines for the ten owner
  functions.
- `MANIFEST.sha256` — hashes for every packet file.

## Regeneration

Run from the repository root with the artifact materialised:

### Regenerate the packet files

```sh
python3 tools/config_fetch_static.py --generate
```

### Verify the manifest

```sh
(cd research/work-items/RE-005-node115-config-fetch && \
 sha256sum -c MANIFEST.sha256)
```

### Run the dedicated tests

```sh
python3 -m unittest tests.test_config_fetch_static -v
```

## Static boundary

No captured instruction was executed.  The bracket censuses
classify each instruction by operand position in fresh objdump
text; register identity follows the entry assignments (rbx = rsi
in the predicate, rbx = rdi in lookup_d, each set once), and the
config slot's reference list uses the series census method, with
each reference pinned byte-for-byte at an instruction boundary.
Whole-struct copies move bytes without naming fields — the
callee's staging, lookup_c's 0x250-byte memcpy and builder_c's
0x98-byte memcpy are enumerated as call sites with pinned
argument setups — so for copied fields the census is a statement
about direct accesses and the copies actually observed.  What
lookup_b does inside the slot it transforms, how lookup_c's
worker converts the entry into the value lookup_d queries, and
who writes the log-state struct at 0x64efd00 are stated as
boundaries in the records, not traced here.
