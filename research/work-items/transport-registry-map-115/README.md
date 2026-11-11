# transport: reconstruct the node #115 registry map path (key hasher 0x477e2b0, entry 0x476f260, reserve_rehash 0x47642d0, record 0x4771f70)

With this packet the four functions can be re-implemented from the bytes alone: a 24-byte two-shape key hash, a 48-byte-bucket SwissTable
entry probe, the full `reserve_rehash` (resize, in-place rehash with swaps, overflow and allocation-failure results, infallible panics) and
the lock-guarded `record(key, f64)` accumulator that keeps a saturating count, a clamped running sum and a maximum per key. The Python model in
`tools/transport_registry_map_115.py` reproduces the real bytes on 15,600 generated cases (state compared byte for byte), and 76 deliberate
errors are all either caught (71) or explained as behaviour-neutral (5).

- Component ID: transport (Network transport; the four functions sit next to the LZ4 block in the text layout; ownership by `transport` is an inference from adjacency, not from a named caller)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference-source text was used
- Claim status: observation (byte-level behaviour of four functions, checked by emulation of the real bytes); names such as "registry", "record" and the field meanings are inference
- Scope included and excluded: included are the four function bodies in full (FDE-validated ranges below) and the external functions they reach through import slots, modelled as stubs. Excluded are the callers of 0x4771f70, the type that owns the map, the stubbed external functions (allocator, memset, memcpy, free, memcmp, lock slow paths), unwinding, and the other hashbrown monomorphisation at 0x47649a0 (a different element size).

## Reproduce

Working directory: repository root, Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`; no external program is started and the binary is only read.

```
python3 tools/artifacts.py verify
python3 tools/transport_registry_map_115.py --out research/work-items/transport-registry-map-115
python3 -m unittest tests.test_transport_registry_map_115
```

The tool refuses to run unless the binary digest matches. Two regenerations into different folders are byte-identical (checked with `diff -r`).
One regeneration takes about 165 s and 360 MB of resident memory; the test file takes about 9 s. `MANIFEST.sha256` lists every file here except itself.

## Evidence

All addresses are virtual addresses of node #115 (the same coordinate system as `node-115-unwind.tsv`). Function ranges come from the FDE table and
the decoder must end exactly on them (`functions.tsv`; the ranges end in `int3` padding after the FDE end for the entry and the other bodies).

| function | range | instructions | executed by the cases |
| --- | --- | --- | --- |
| key hasher | 0x477e2b0..0x477e5b2 | 174 | 174 |
| entry | 0x476f260..0x476f480 | 138 | 137 |
| reserve_rehash | 0x47642d0..0x47649a0 | 429 | 410 |
| record | 0x4771f70..0x47721f0 | 157 | 145 |

`coverage.tsv` lists every instruction with a 0/1 flag. The 32 instructions never executed are: padding `nop`s at 0x476f384, 0x47646a7 and 0x47647e7;
0x47645f4 and 0x47645f6 (the `bucket_mask + 1 == 0` arm, which a real table cannot reach); 0x47647d6..0x47647e2 (the group-0 fix-up inside the
in-place rehash, see Limits); 0x4764963..0x476498d and 0x47721c1..0x47721e3 (unwind landing pads and the panic call, entered only on an exception).

Observed structure (all re-derived from the bytes; the model in the tool is the executable statement of it):

1. **Key hasher 0x477e2b0** (`rdi` hasher state, unused; `rsi` key). The 24-byte key has two shapes: word 0 non-zero means (pointer, length, u32 tag);
   word 0 zero means (0, pointer, length) with no tag. The bytes are folded with two 64-bit lanes seeded with 0x243f6a8885a308d3 and
   0x13198a2e03707344: length 1..3 reads bytes 0, len/2 and len-1; 4..7 reads two overlapping u32; 8..16 reads two overlapping u64; above 16 bytes it
   folds 16-byte chunks (a 128-bit multiply of `lane ^ word0` by `word1 ^ 0xa4093822299f31d0`, high xor low) two lanes at a time, one extra chunk when
   the chunk count is odd (then the lanes swap), and finally the last 16 bytes. The result is `(len ^ hi ^ lo) * 0x1427bb2d3769b199`; the tagged shape
   continues with `((x + tag) * 0xf1357aea2e62a9c5 + 0x1393720a3247e767)`, the untagged shape with `x + 0x9b99c6de196cc6f8`; both end in `rol 20`.
2. **Entry 0x476f260** (`rdi` result, `rsi` map, `rdx` key). Hash, control byte `h2 = hash >> 57`, 16-byte group probes at `hash & mask` with triangular
   stride 16. A candidate matches only when both keys have the same shape, the u32 tags are equal (low 32 bits only) and the lengths and bytes
   match (memcmp import slot 0x64df9f8). Result words: occupied = `[0, bucket end pointer, map]`; vacant = `[map, hash, key word 0..2]`. On a miss with
   `growth_left == 0` it first calls `reserve_rehash(map, 1, hasher, infallible)` through slot 0x64eb138.
3. **reserve_rehash 0x47642d0**: `new_items = items + additional` (carry means capacity overflow). If `new_items <= full_capacity / 2` the table is rehashed
   in place (FULL becomes DELETED, DELETED/EMPTY become EMPTY, 16-byte tail copy, then every DELETED bucket is re-hashed and moved or swapped with a DELETED
   target until it settles; `growth_left = capacity - items`). Otherwise it allocates a table of `capacity_to_buckets(max(new_items, full + 1))` buckets
   (4/8 below capacity 8, else next power of two of `cap * 8 / 7`; limit 0x1ffffffffffffffe, 48-byte buckets with `jo`/carry checks and a 0x7fffffffffffffee
   size ceiling), fills control bytes with 0xff, re-inserts every FULL bucket through the same group search, swaps the table in and frees the old
   allocation `(ctrl - round16(mask * 48 + 63), size, flag)` unless it was the shared empty group. Results: `0x8000000000000001` ok, `0` capacity overflow,
   `0x10` with size in `rdx` allocation failure; with the infallible flag the two errors become the panic slots 0x64df6b8 and 0x64df490.
4. **record 0x4771f70** (`rdi` lock byte, map at `rdi + 0xb8`, `rsi` key, `xmm0` value): byte lock taken by `cmpxchg 0 -> 1` (slow slot 0x64e01f8 with
   1e9), entry, insertion of a vacant key into the first EMPTY/DELETED slot of its probe (with the group-0 fix-up for tables under 16 buckets), buckets are
   key(24) + `count` + `sum` + `max`. Update: `count = min(count + 1, u64::MAX)`; `sum' = clamp(sum + v)` where a result that is negative (except -0.0), NaN or
   -inf becomes +0.0 and +inf becomes the f64 stored at 0x459090; `max' = (max > v) ? max : v` (the `maxsd` rule, so NaN replaces the maximum); the
   lock is released by `cmpxchg 1 -> 0` (slow slot 0x64e0f38 when the byte is not exactly 1).

## Implementation and comparison

Independent Rust path: not yet implemented. The reconstruction here is the executable Python model plus its comparison with the real bytes; no Rust
source was written or compared and no gate is requested.

- `tools/transport_registry_map_115.py`: (1) the offline x86-64 interpreter used by merged tools in this repository, with `lock cmpxchg` (0f b0) and
  `pcmpgtb` added; (2) the model: `key_hash`, `Model.find/entry/reserve/_rehash_in_place/_resize/insert_vacant`, `saturate_sum`, `record_update`;
  (3) `Rig`, which writes a model table (control bytes, 48-byte buckets, header words) into interpreter memory, runs the real bytes with the external
  slots served by deterministic stubs, then reads the table back and compares header, every control byte, every FULL bucket, return words, allocator
  and free calls, panic kind, lock byte and slow-path calls; (4) generators; (5) controls and the evidence writer.
- Cases (fixed seeds, `measure.json`): 15,600 = hash 3,200 + entry 4,000 + reserve 4,800 + record 3,600. Generators cover both key shapes, lengths
  0..150, equal contents at different pointers, tags differing only above bit 31, tables of 0 (shared empty group), 4, 8, 16, 32, 64 and 128 buckets,
  tombstones, clusters of 16..41 full buckets, runs of equal hashes (second and third probe group), tiny tables (group-0 fix-up on insertion),
  forced `growth_left = 0`, huge `additional` values (capacity overflow, size ceiling, allocation failure), both fallibility flags, special f64
  values (zeros, subnormals, NaNs, infinities, extremes), a saturated count and lock bytes 0, 1 and 3.
- `cases.tsv` keeps one row in 5 to 8 per suite (2,720 rows) with a 12-hex digest of the input and the executed step count; the remaining cases are
  regenerated by the tool. `classes.tsv` gives the per-class counts.
- Negative controls (`controls.tsv`, 76): 54 byte mutants of executed instructions (36 condition flips, 12 shift/compare/add immediates, 4 64-bit hash constants,
  `addsd -> subsd`, `maxsd -> minsd`), 13 deliberately wrong model variants (constants, rotate 19,
  `h2` from bit 56, 64-bit tag compare, unclamped sum, non-saturating count, minimum instead of maximum, wrong small-capacity rule, missing fix-up,
  growth always consumed, wrong large capacity), 4 corrupted expectations (control byte, bucket word, `growth_left`, allocation address) and
  5 corrupted inputs (digest differing in the last digit, range ending one byte early, address inside a function, read below every mapping, key
  pointing outside every mapping). Detection compares the first diverging case in the first 300/1500/700/500 cases of the four suites.
- `equivalent-mutants.tsv`: five flips that cannot change behaviour, each with its reason (odd-group test whose extra group is overwritten by the
  tail copy; compare 9 versus 8 for the 8-bucket capacity; two record branches whose targets set the same registers; one record branch whose
  skipped move is a no-op). Detected + equivalent = 76 = all mutants built; none was dropped for not being caught.

## Results and limitations

`measure.json`: cases 15,600; negative_controls 76; negative_detected 71; equivalent 5; undetected_unexplained 0. Tests: 18 in
`tests.test_transport_registry_map_115` (about 9 s).

Limits:

- The external functions are stubs chosen from register use (allocator `rdi` size, memset, memcpy, free, memcmp, the two lock slow paths); their
  real bodies are not analysed here. The allocator stub fails above 4 MiB to reach the failure arms.
- The in-place group-0 fix-up (0x47647d6..0x47647e2) was not reached; neither did the model reach it in a 60-state search per tiny case, so it may
  be unreachable, but that is not proven. Unwind landing pads and the panic call were not exercised (no exception is simulated).
- The two 64-bit constants in `reserve_rehash` that only matter for astronomically large capacities (0x1ffffffffffffffe and the /7 multiplier) were
  not mutated: a one-bit change of the multiplier did not change the bucket count for any value tried near powers of two, so no case
  separates it. This is a validation gap, not a claim.
- Hasher state `rdi` is never read; the seeds are constants. The meaning of the map (which subsystem records which keys) is unresolved.
- No progress gate is requested; this does not cover the whole `transport` component (framing, LZ4, channels, rate limits, reconnects).

Next question: find the callers of 0x4771f70 (the keys and values they pass) and the owner of the lock byte at `rdi`, to tie this registry to
a named transport subsystem.
