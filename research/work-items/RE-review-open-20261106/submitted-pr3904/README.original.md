# RE-011: reconstruct the fallible storage load 0x433bcf0 and its map entry 0x3ed6d80 (node #115)

This packet lets you rebuild the second EVM storage-load body of node #115 from end to end. That body is the one the
sstore twin `0x2977cd0` reaches through GOT `0x64e6d98`. It is now a runnable pure-Python function: the storage map entry
`0x3ed6d80` (hash, probe, reserve before Vacant), the warm/cold decision against the access-list map, the skip return,
the created-account zero, the two-stage database read in which **every database error is folded into the value 0**, the slot
insertion (original = present = value) and the journal tag 9 entry. It matches the real machine code in
4,200 of 4,200 cases, and 29 of 29 negative controls are detected.

- Component ID: `evm` (task RE-011, EVM execution / state access)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `a1a8d54318c2713c0d4b874053e5eb62b7ee9b11`; no reference source was copied
- Claim status: observation (bytes, extents, relocations, evaluated behaviour) plus inference (the names "storage load",
  "warm/cold", "created", "account/storage read" are inferred roles, not recovered symbols)
- Scope included: the whole body `0x433bcf0..0x433c5c9`; the entry `0x3ed6d80..0x3ed6edc`; the key hasher
  `0x46ef2f0` + `0x46ef360` (run real, together with the byte hasher `0x1770830`).
  Scope excluded: the database reads `0x3d48970` / `0x3d48700` (already described by the merged
  `RE-011-storage-read-115` packet; stubbed here with explicit result words); the storage reserve `0x3ee1680`, journal
  grow `0x43bc980` and free `0x635de30` (stubbed with the hashbrown / Vec rules and checked arguments). There is no
  Rust implementation, and no gate is requested.

## Reproduce

From the repository root with Python 3 (standard library only, no binutils, nothing is executed):

```
python3 tools/re11_storage_cache_load115.py --out research/work-items/RE-011-storage-cache-load-115
python3 -m unittest tests.test_re11_storage_cache_load115
```

The tool checks the input SHA-256 first and fails on any other digest. It reads sections with `tools/elf_index.py` and FDE
extents with `tools/fde_extents.py`. It applies `.rela.dyn` RELATIVE addends to every GOT word it follows and
evaluates the real code bytes with an in-file concrete x86-64 evaluator (unknown forms raise). Two runs with different
`PYTHONHASHSEED`/`TZ` and a binutils-free `PATH` produced byte-identical output. A full run takes about 40 s.
`MANIFEST.sha256` lists the hashes of the outputs.

## Evidence

Coordinates are virtual addresses in node #115; `.text` VA equals the file offset plus the section delta read from the
section header. Every row of `constants.json` is re-read from the ELF bytes on every run.

FDE extents (`constants.json` → `functions`): `0x433bcf0` 2,265 bytes / 524 instructions, `0x3ed6d80` 348 / 96,
`0x46ef2f0` 106 / 28, `0x46ef360` 127 / 39. Relocated slots: `0x64e6d98 → 0x433bcf0` (the fallible load),
`0x64e7028 → 0x3ee1680` (reserve), `0x64e68e8 → 0x43bc980` (journal grow), `0x64df4a0 → 0x635de30` (free),
`0x64dfa80 → 0x1770830` (byte hasher), `0x64dfa78 → 0x64ffe90` (global seed block, NOBITS, so synthetic seeds are used).

Argument ABI observed from the body: `rdi` = block {+0x0 account, +0x8 journal Vec, +0x10 access-list map, +0x18
&database, +0x20 u32 transaction id, +0x24 20-byte address}; `rsi` = 32-byte key; `dl` = skip flag. Return: `rax` =
slot pointer (bucket + 0x20) or the account pointer, `dl` = 0 warm / 1 cold (journalled) / 2 skipped.

Hand excerpt of the decision points (from objdump, for reading only; the evidence files do not use it):

```
433bd38  call 3ed6d80              ; entry: Occupied {0, bucket_end, table} / Vacant {table, hash, key}
433be75  cmp %r13d,-0x8(%r12)      ; slot transaction id == current ?
433be7c  cmpb $0x0,-0x4(%r12)      ;   and cold byte == 0  -> return (slot, 0)
433bf84  test %bpl,%bpl            ; cold + skip -> dl = 2
433bf8d  test $0x1,%r12b           ; status +0x8c bit 0 (created) -> value 0, no read
433bfd7  call 3d48970              ; account read: tag 2 = Err (dropped), 0 = None -> value 0
433c105  call 3d48700              ; storage read at database +0x1230: tag 2 Err -> 0, tag bit 0 -> value
433c4df  movb $0x9,(%rax,%rcx,1)   ; journal entry tag 9 for a cold access
```

Observations confirmed by evaluation (cases in `cases.tsv`, classes in `outcome-classes.tsv`):

1. The entry `0x3ed6d80` hashes the key as `fold(fold(k1^g0, k0^seed) ^ k2, k3^g0)` over four little-endian limbs.
   When the key is missing it calls reserve(table, 1, &table.seed, 1) **before** returning Vacant if growth_left is 0, so a
   later skip return (dl = 2) still leaves the table grown (`skipped/miss/reserve`: 307 cases).
2. Warm: an Occupied slot with the current transaction id and cold byte 0 returns at once. Otherwise the address is
   probed in the access-list map (64-byte buckets, seed at +0x20). An empty map, a missing address or an address with
   an empty key set counts as cold, and no key hash is computed. Otherwise the key is hashed by `0x46ef2f0` (seed by
   reference; a byte-twin shape of `0x4e52a90`) and probed in 32-byte buckets.
3. Cold + skip returns `dl = 2` with the slot pointer (Occupied, slot untouched) or with the **account pointer**
   (Vacant).
4. An Occupied refresh copies present → original, writes the transaction id and clears the cold byte. A re-check at
   `0x433c52b..0x433c58c` repeats a comparison that already failed, so its "unchanged" arm `0x433c57d` is unreachable.
5. Vacant value. Status bit 0 gives 0 without any read. Otherwise the account read runs. Err (tag 2) drops its payload:
   inner kind 0/1 nothing, 2 calls the boxed error's first vtable word, ≥3 frees `(ptr = w3, size = w2)` when w2 ≠ 0. A
   `cmp $3` at `0x433c00d` is dead. The result is value 0. None (tag 0) gives value 0 without a storage read. Any other
   tag runs the storage read with `{key, address}` at database +0x1230. Its Err is dropped in the same way and gives 0;
   tag bit 0 gives words 1..4 as the value; other tags give 0. The account dword at +0x78 selects between two
   byte-identical call sequences, so it has no effect.
6. Insertion uses the hashbrown find-insert-slot with the small-table wrap fix. It writes the h2 control byte and its
   mirror, decrements growth_left only for an EMPTY byte, and fills the bucket with {key, value, value, txid, 0}. Bytes
   0x65..0x67 stay as they were.
7. A cold access pushes a 0x58-byte journal entry: tag 9, address at +1, key at +0x18, and 3 padding bytes at +0x15
   that hold whatever was last at `rsp+0x60` (the entry tag word, the account-read tag word, or the key copy). Bytes
   +0x38.. are not written. When length == capacity, grow `0x43bc980` is called first.

## Implementation and comparison

The independent Rust implementation is not yet implemented. The executable reconstruction is the Python function `load()` in
`tools/re11_storage_cache_load115.py` (plus `hash_slot_key`, `hash_addr`, `hash_key`, `bytes_hash`, `Table`).
Each case lays out synthetic memory for the account, the storage table, the access-list map with its key sets, the journal
Vec, the database reference and the error box. It runs the real bytes from `0x433bcf0` with `0x3ed6d80`, `0x46ef2f0`,
`0x46ef360` and `0x1770830` executed, and compares five things with the model:
the return pair, the ordered callee events (reserve, reads, drop, free, journal grow) with their arguments, every
journal entry byte, the decoded storage table (mask, growth_left, items, seed, every control byte including the mirror,
and every bucket byte), and the callee-saved registers and stack. All other input bytes must stay unchanged.

Case generation (`all_cases`, seeded SHA-256 stream) mixes several table shapes: hits, misses, dense tables (7/8 full),
and clustered tables whose keys hash into the probe window of the looked-up key (this covers the full-group continuations
at `0x3ed6e5e` and `0x433c591`). It also mixes tombstones, zero growth (reserve), journal at capacity, all database result
kinds, transaction ids `0`, `1`, `0x80000000`, `0xffffffff`, and skip registers whose low byte is or is not zero.

Negative controls (`negative-controls.tsv`, 29/29 detected):

- 17 wrong reconstructions: limb swap, always re-check, ignore skip, no original copy, created reads the database,
  present zero, always journal, address word swap, length prefix 1, no rotate, no wrap fix, no mirror, wrong
  byte-hasher branch, empty key set treated as warm, None still reads storage, any tag is Some, always free.
- 10 single-byte code mutants: status bit, journal tag, Some bit, both bucket strides, warm-map and key-set
  strides, key-set items compare, database offset 0x1230, entry stride, h2 shift.
- 2 input controls: one flipped `.text` byte (digest rejected), and an address past `.text`.

## Results and limitations

- `summary.json`: 4,200 cases, 0 mismatches. Executed instructions: `0x3ed6d80` 96/96, `0x433bcf0` 518/524,
  `0x46ef2f0` 24/28, `0x46ef360` 29/39.
  The 6 missed instructions in the body are the unreachable re-check arm `0x433c57d..0x433c58c` (5) and the
  second-group loop jump `0x433c5b2`. The missed hasher instructions are the `len == 0` and `len >= 0x41` arms, which a
  single 32-byte write cannot reach.
- Outcomes (from `outcome-classes.tsv`): warm 1,319, cold 1,611, skipped 1,270. Reserve was reached in 923 cases,
  journal grow in 831, error-box drop in 72 and free in 104.
- Limits: the database reads, reserve, grow and free are boundaries modelled by their argument/result contract, not
  reconstructed here. The seed block is NOBITS, so its values are synthetic. The callers `0x2994990` / `0x2994490` and
  `0x2977cd0` are not covered. Swallowing database errors as value 0 is an observation about this body only; whether
  callers detect such errors elsewhere is unresolved.
- No PROGRESS gate is requested.
- Next question: does the gas-charging caller `0x2994990` read the dl = 0/1/2 result of this body the same way the
  infallible `0x4e33680` callers do, and does any path report the swallowed database error?
