# fees: reconstruct fee-ledger index-map pushes, vacant-entry completion and reserve_rehash (0x3ec8b70, 0x3ec7a90, 0x4718060, 0x4717fb0, 0x3ed89a0, 0x3ee1cc0)

This packet lets a reimplementation of the fee ledger's two keyed maps build the "vacant entry" half of
`entry(key).or_default()` exactly as node #115 does: where a new row's index is stored in the hashbrown control
array, how both concrete `reserve_rehash` bodies rebuild their tables, how the entry vector grows (0 -> 1 -> 2 -> 4 -> 8),
which bytes of the default value are written, which two panics exist and what a corrupted table or vector length does
to the returned row.  Six routines are decoded from ELF bytes; 10,600 generated cases are compared byte-for-byte with
a closed-form model, including 1,712 executions of the two rehash bodies.  All 125 negative controls are detected.

- Component ID: `fees`
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main 0781ce04826eeefd89fe336cb8ea073be0c1de30; no reference source copied
- Claim status: observation (decoded bytes, run on modelled memory) plus inference (the closed-form model; stated below)
- Scope included and excluded: the four push/entry functions and the two concrete rehash bodies reached through GOT
  slots 0x64e63e0 and 0x64e6340; excluded: the `memcpy`/`memmove`/`memset` and allocation/deallocation boundaries,
  vector reallocation helper 0x43bd550, and the old-table drop helper 0x3ddd030, each modelled as a narrow external contract;
  prior art: `RE-010-builder-approval-115` observes the miss path of 0x3ec8b70 in
  prose (selected path with spare capacity) and `RE-001-node115-spot-record-update-order` lists 0x4717fb0 as a call
  target, neither reconstructs or compares the functions; the SipHash key hashers and group probes of the sibling packet
  (`fees-ledger-maps`), the callers of the entry completions and the maps' owners.  No component gate is requested.

## Reproduce

```
python3 tools/artifacts.py verify
python3 tools/ledger_push_115.py --out research/work-items/fees-ledger-push-115
python3 -m unittest tests.test_ledger_push_115
(cd research/work-items/fees-ledger-push-115 && sha256sum -c MANIFEST.sha256)
```

Only the Python standard library and the shared ELF/FDE readers are used; no external program runs and the node is
never executed.  The tool checks the binary's SHA-256 first, then writes `evidence.json`, `instructions.tsv`,
`vectors.tsv`, `controls.tsv` and `measure.json` deterministically (no clock, no randomness: the vector generator is
a fixed xorshift64* seeded with 0x115CD).  The run takes about 20 s and well under 0.5 GB.
`vectors.tsv` lists every third case; `evidence.json` holds the SHA-256 of all 10,600 rows.

## Evidence

Coordinates are virtual addresses of the loaded image.  Function bounds come from `.eh_frame_hdr`/FDE records; the
table decoder must land exactly on each FDE end.

| function | VA range | instructions | role |
| --- | --- | --- | --- |
| push_a | 0x3ec8b70-0x3ec8f88 | 253 | index-map push, 0x100-byte rows (value 0xe0, hash at +0xe0, 20-byte key at +0xe8) |
| push_b | 0x3ec7a90-0x3ec7f05 | 265 | same push, 0x70-byte rows (value 0x50, hash at +0x50, key at +0x58) |
| entry_a | 0x4718060-0x471813c | 40 | vacant/occupied completion that builds the 0xe0-byte default value and calls push_a |
| entry_b | 0x4717fb0-0x4718056 | 37 | the same for the 0x70-byte row map; calls push_b |
| reserve_rehash_a | 0x3ed89a0-0x3ed9141 | 454 | concrete hashbrown table reserve/rehash body called by push_a |
| reserve_rehash_b | 0x3ee1cc0-0x3ee2461 | 455 | separate concrete instantiation called by push_b |

Observations (each is checked on every vector, see `controls.tsv` and `evidence.json`):

1. Arguments of the push routines: rdi = out record, rsi = table {ctrl, bucket_mask, growth_left, items}, rdx = entry
   vector {cap, ptr, len}, rcx = hash, r8 = 20-byte key, r9 = value.  The out record gets {&vector, ctrl - 8*slot,
   &table, hash} and rax = out.
2. Slot search: SSE2 group load of 16 control bytes at `hash & mask`, `pmovmskb` of the high bits, `tzcnt`; triangular
   probe stride 16, 32, ... ; if the chosen byte is full (tiny tables, mirrored tail) the first empty byte of group 0 is
   used.  The budget is spent only when the byte is EMPTY (low bit set): `growth_left -= ctrl & 1`.
3. When `growth_left == 0` and the slot byte is EMPTY the routine calls the matching decoded `reserve_rehash` body
   through the GOT with `(table, 1, entries, len, 1)`, reloads ctrl/mask and searches again. The two function bodies
   execute on the generated corpus; output rows and control bytes are checked against the separate `RawTable` model.
4. The control byte written is `hash >> 57` (the 0x39 shift), and its mirror at `((slot - 16) & mask) + 16`.
5. `items == u64::MAX` panics at Location 0x647aa78 *after* the control byte and the budget were already written;
   otherwise the bucket word at `ctrl - 8*(slot+1)` receives the old `items` (not the vector length) and `items += 1`.
6. Vector push: when `len == cap` the new capacity is `min(2*len, limit)` (limit 0x7fffffffffffff for 0x100-byte rows,
   0x124924924924924 for 0x70-byte rows); the exact-growth path (`len + 1`) is used when the doubling adds at most one
   row (len 0 and 1) or when the doubling reallocation failed; a failed second attempt calls the allocation-error GOT slot
   0x64df498 with (bytes, align).  The row is stored as value, hash, key, with 4 trailing stack bytes.
7. Entry completions: a null table pointer selects the occupied arm; the index at `bucket - 8` is bounds-checked against
   the vector length (Location 0x6493b60) and the row address is `ptr + index * stride`.  The vacant arm builds the default
   value on the stack, calls the push, and bounds-checks the stored index the same way, so a table whose `items` differs
   from the vector length returns another row or panics at 0x6493b60.  Written default bytes: map A offsets 0x00, 0x80-0xc4
   with 8 at 0x88 and 0xa8; map B the whole 0x50 bytes with 8 at 0x08 and 0x28.  Bytes of the default value that are not
   written (map A) are stack leftovers; the model leaves them out of the comparison.

Raw material beside this record: `instructions.tsv` (every decoded instruction of all six functions, bytes included),
`vectors.tsv` (every third case: shape, items, capacity, hash, failure injection and observed result),
`controls.tsv` (every control and its verdict), `evidence.json` (bounds, counts, panic census, unexecuted addresses).

## Implementation and comparison

`tools/ledger_push_115.py` contains (a) the shared table decoder and interpreter, (b) a closed-form `model_push`
and `model_entry` (hashbrown control array model, resize policy `buckets_for(max(items+1, full_cap+1))`, vector growth
policy, default values), (c) the case generator, mutants, wrong models and corrupted inputs.  A case is built in
modelled memory, the real bytes run, the table bytes, the vector header, every row, the out record and the returned
address are read back and compared with the model.

External contracts used (not claimed as decoded here): `memcpy` and `memmove` copy their specified byte ranges,
`memset` writes its specified byte value, the allocator returns a fresh modelled arena and deallocation is a no-op,
the old-table drop helper 0x3ddd030 is stubbed as a no-op for the old allocation, and vector reallocation 0x43bd550 returns either
`{0, new_ptr}` after copying the old rows or `{1, bytes, 8}` on injected failure. These boundaries do not choose the
new hash table size, reinsertion order, control bytes, bucket indices or growth counter; those are written by the
executed rehash bytes. Each rehash body decodes completely, while only the instructions reached by this input corpus
are claimed as executed: see `executed_instructions` and `unexecuted` in `evidence.json`.

No Rust path is implemented yet, so there are no two-build or Cargo.lock results: "not yet implemented".

## Results and limitations

- Vectors: 10,600 (push_a 3,000, push_b 3,000, entry_a 2,300, entry_b 2,300), all agree with the model.  Panics seen:
  185 items-overflow (0x647aa78), 147 bounds (0x6493b60), 78 allocation errors.
- Negative controls: 125 listed, 125 detected: 99 one-byte mutants (including one tag-shift mutation in each rehash
  body; inverted branches, shift counts, displacements,
  immediates, imul factors), 14 wrong models (8-bit and 6-bit tags, budget spent on every slot, linear vector growth,
  stored index = vector length, no table growth, corrupted hash, truncated key, two entry-level variants) and 12 corrupted
  inputs (digest, empty input, non-FDE address, unmapped and `.bss` address, unlisted opcode, truncated ULEB128, four
  patched-image self-checks, a stale rows list).  8 further mutants survive the control slice or sit on unexecuted code
  and are listed as such in `controls.tsv`, not counted.
- The existing 63 push/entry instructions never executed remain outside the observations. In addition, each rehash body
  has 256 decoded instructions not reached by this corpus; these include exceptional and alternate allocation/rehash
  paths. They are listed in `evidence.json` and are not claimed behavior.
- Among push/entry instructions, the corpus does not execute unwinding landing pads, panic arms that need a table with no empty byte or a
  wrapped probe, and the `len == new capacity` call of GOT slot 0x64e63d8/0x64e6338, which no vector size reaches.
  Those are decoded but unverified.
- Limits: tables up to 64 buckets and vectors up to a few dozen rows; no DELETED-only tables; external memory-management
  contracts above are not verified against their own bodies; value bytes the callers never write are masked.  The key hashers and group
  probes are in the sibling `fees-ledger-maps` packet; the callers that pass hash, table and vector (for example
  0x3c10000) are not covered.  No progress gate is requested.

Next question: the callers of entry_a/entry_b (0x3c10000 and the other `or_default` sites), including the f64 price clamp
and the vector clone they run after the entry returns, and the real body behind vector reallocation helper 0x43bd550.
