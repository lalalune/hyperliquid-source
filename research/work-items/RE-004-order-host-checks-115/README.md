# RE-004: reconstruct the four order market host checks and their lookup callees in node #115

This packet makes it possible to re-implement, from bytes, the four host-slot checks that the order market-state check consults (per-key state byte, set/index-map membership chain, three-map chain, and the 10^k notional scaling with its overflow flag) together with the u64 map get, the ring binary search, the SipHash-1-3 hasher and the three hashbrown group probes they sit on: 11 bodies run as real code and agree with independent Python rules on 37,800 cases, with 185 of 185 negative controls detected.

- Component ID: RE-004 (order admission; checks reached through the exchange order path).
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main 0781ce04826eeefd89fe336cb8ea073be0c1de30 (no reference source was used; labels below are inferences from behaviour)
- Claim status: observation for every address, layout offset and branch outcome (executed on the bytes and compared); inference for the role names
- Scope included and excluded: included are the 11 bodies below. Excluded: the caller 0x22e7f80 and its call-through-slot sites (not re-owned), the host-side meaning of the stored values, the allocator and drop glue (never reached by these bodies), and any gate claim. No progress gate is requested.

## Reproduce

Working directory: repository root, no network, the binary is parsed and executed only by the Python evaluator in `tools/decimal_scaled_u64.py` (bytes are read, never run natively; no objdump, readelf or subprocess in the tool or tests).

```
python3 tools/artifacts.py verify
python3 tools/order_host_checks_115.py --out research/work-items/RE-004-order-host-checks-115
python3 -m unittest tests.test_order_host_checks_115
python3 tools/catalogue.py --check
```

The tool checks the input SHA-256 first and refuses a different binary. `--out` rewrites every evidence file byte-for-byte (two runs with different hash seeds and time zones were compared with `diff -r`); the full run takes under one minute and stays below 1 GB resident. Hashes of the generated files are in `MANIFEST.sha256`.

## Evidence

Coordinates are virtual addresses of the loaded image; every body starts at an FDE start (`functions.tsv` lists extent, instruction count, direct calls and the SHA-256 of the body bytes).

| body | VA | bytes | observation |
| --- | --- | --- | --- |
| `sip_hash` | 0x47172c0 | 371 | SipHash-1-3 of one u64: key halves in rdi/rsi, word in rdx, calls the real hasher write 0x45927a0 for the 8 data bytes, then 1 compression round per block and 3 finalisation rounds (`xor 0xff` on v2) |
| `probe_a24` | 0x3ed2180 | 244 | hashbrown group probe: 16-byte control group, h2 = hash >> 57, entry index word at ctrl - 8*(slot+1), entries stride 0x18 with the key at +8; returns 1 and the entry index, or 0 |
| `probe_b160` | 0x3ed2280 | 244 | same probe, entries stride 0xa0, key at +0x98 |
| `probe_c120` | 0x3ed2b10 | 244 | same probe, entries stride 0x78, key at +0x70 |
| `ring_search_16`, `ring_search_16_twin` | 0x4556d70, 0x24c5280 | 289 each | binary search over a VecDeque of 16-byte rows keyed by the first u64; returns (0, logical position) when found, (1, insertion position) otherwise; the two bodies have the same SHA-256 |
| `map_get` | 0x2db0710 | 234 | u64 key -> pointer to the value cell or null; the map header is either a ring (cap, ptr, head, len; value at row + 8) or, when the first word is 0x8000000000000000, a B-tree (root, height) with keys at node + 8 + 8i, values at +0x60 + 8i, length u16 at +0xba, edges at +0xc0 |
| `check_a` | 0x3c11a70 | 278 | record index -> record key (stride 0x20, key at +8, count at +0x20) -> state byte from a u64 map at +0x2f8 (ring or B-tree with u8 values at node + 0x64, edges at +0x70); absent key returns 1 |
| `check_b` | 0x3c07600 | 416 | key -> B-tree set at +0x1b8/+0x1c0 (edges at +0x68) returns 1; else key -> index map A (siphash keys at +0x38/+0x40) -> value -> index map B at +0x90 (entries stride 0xa0): returns 0 when A misses, 1 when A hits but B has no such value, 2 when it does |
| `check_c` | 0x3c09af0 | 410 | key -> map A -> value -> map B at +0x48 -> value -> map C at +0xd8 (entries stride 0x78, key at +0x70); returns 1 only when the C entry field at +0x30 equals the first value, else 0 |
| `check_d` | 0x3c4b1a0 | 212 | amount * 10^(hi - lo) where lo/hi are the bytes at +0x48/+0x49 of the 0x158-byte record selected by the index; returns (1, product) or (0, low 64 bits) on overflow |

Observations that came out of running the bytes and are fixed by the cases:

- `check_d` builds the power of ten bit by bit (10, 10^2, 10^4, 10^8 with 64-bit multiplies, then 10^16 with an overflow-checked multiply). The accepted difference range is therefore 0..=19; 20..=255 and a negative difference (hi < lo, byte borrow) reach the scale panic message at 0x6476a48 through the one-argument panic helper; an index past the record count reaches 0x64768d8. The product overflow flag is an ordinary return value (0), not a panic.
- All three probes treat a slot index word >= the entry count as a bounds panic with arguments (index, count) before comparing keys; the cases corrupt a slot word on purpose and every body panics with exactly those arguments (`cases.tsv`: 587, 459 and 449 generated panics for the three probes, 440 for check_b and 791 for check_c).
- A single-entry index map is never hashed: the bodies compare the one stored key directly (generated cases cover this for A in check_b and check_c, and for B and C where reached).
- `check_a` returns the stored state byte, including 0; the value 1 for an absent key is only distinguishable by the map content, which is why the cases pair a stored 0 with an absent key.
- `ring_search_16` and `ring_search_16_twin` are byte-identical bodies at two addresses (same SHA-256 in `functions.tsv`).
- The four host slots 0x64e4ec0, 0x64e4ec8, 0x64e4ed0, 0x64e4ed8 are relative relocations whose addends are 0x3c11a70, 0x3c07600, 0x3c09af0 and 0x3c4b1a0 (`slots.tsv`).

Evidence files (all produced by the tool): `functions.tsv`, `slots.tsv`, `cases.tsv` (case classes and counts per body), `field-reads.tsv` (every memory field the bodies read, by region, offset and width, with read counts), `mutants.tsv`, `spec-flaws.tsv`, `damage.tsv`, `measure.json`.

## Implementation and comparison

There is no Rust path in this packet ("not yet implemented"); the reconstruction is an executable Python model checked against the bytes. `tools/order_host_checks_115.py` loads the ELF through the repository's `decimal_scaled_u64.Image`, extends its concrete evaluator with the instructions these bodies need (rol, cdqe, call through register, movd, punpcklbw, pshuflw, pshufd, pcmpeqb, pcmpeqd, pmovmskb) and runs each body on a freshly built memory image. The only stubs are the four panic helpers (their arguments are logged and compared). Nothing else is hooked: the hasher write, the ring search under `map_get` and `check_a`, and the hash and probe calls inside `check_b` and `check_c` all execute their own bytes.

Models, written independently of the bytes: a SipHash-1-3 implementation; a hashbrown table builder (control bytes with the mirrored trailing group, triangular probing, deleted markers, index words below the control bytes); a B-tree builder with the three node layouts above (leaf capacity 11, heights 0 to 2); a ring placer with wrap; and one rule function per body.

Case counts per body (`CASES` in the tool, produced with the default settings): sip_hash 1,800; probe_a24 3,600; probe_b160 2,700; probe_c120 2,700; ring_search_16 2,400; ring_search_16_twin 1,800; map_get 3,600; check_a 3,900; check_b 5,400; check_c 5,400; check_d 4,500; total 37,800, 0 mismatches. Case classes include ring with and without wrap, B-trees of heights 0 to 2, empty and root-less maps, hash clusters that force multi-group probing, same-hash different-key misses, deleted markers, corrupt slot words, and the d = 0 / 1..15 / 16..19 / 20+ / borrow classes of `check_d`.

Negative controls (185, all detected; `measure.json`): 155 branch-flip and imm8 byte mutants of the bodies that the 160-case battery kills (2 further mutants survived and are listed as survivors in `mutants.tsv`, not counted: `probe_b160` at 0x3ed231f and `check_b` at 0x3c07770; they were not analysed further); 15 deliberately wrong rules (`spec-flaws.tsv`: wrong hash key half, off-by-one slot, late insertion position, first-row pointer, absent as 0, wrong key, ignored tree set, chain always 2, missing field compare, range limit 18, power off by one, overflow reported as success); 15 damage and range controls (flipped byte changes the digest and is restored, mid-function starts refused for all 11 bodies, unpopulated context refused).

## Results and limitations

Metrics: 37,800 cases / 0 mismatches; 185 negative controls / 185 detected (155 mutants + 15 flawed rules + 15 damage); 26 unit tests, no skips; data files are about a third of the packet lines.

Limits, stated plainly:

- Role names (`check_a`..`check_d`, state byte, notional scaling) are inferences from observed behaviour; the packet does not show which game-rule fields the stored values correspond to.
- The `check_b` result 2 branch whose entries pointer is null (`cmpq $1, 0x98(...)` then `sbb`) is reachable only with an inconsistent table and is not generated.
- Hash table shapes are those a standard hashbrown insert produces; tables with a full control group and no empty byte (probe never terminates in practice) are out of scope.
- Callers of the four slots (the market-state check 0x22e7f80) and the producers of the stored tables are not analysed here, and no component gate is requested.

Next question: the producers of the `check_b`/`check_c` index maps and of the B-tree set at +0x1b8 (which block-level event inserts and removes the keys), starting from the writers of the hash-key halves at +0x38/+0x40.
