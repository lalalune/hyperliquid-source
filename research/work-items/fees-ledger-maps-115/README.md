# fees: node #115 ledger map helpers, SipHash-1-3 key hashers, four hashbrown probes and the map entry (0x4717440, 0x47175b0, 0x3ee6280, 0x3ee69c0, 0x3ed2180, 0x3ed2280, 0x4717c50)

This packet makes it possible to reconstruct, as executable code, how node #115 looks up one row of its keyed ledger maps: the 20-byte address key and the 16-byte key are hashed with SipHash-1-3 under two hasher words, a 16-byte-group hash table (7-bit tag, triangular probe, EMPTY ends the search, DELETED never matches) is probed, the stored bucket value is bounds-checked against the entry count and compared with the key, and the map entry turns a stored index into a row address. `tools/ledger_maps_115.py` runs the real bytes of seven functions on 10200 generated inputs and checks every outcome against closed-form reconstructions (a SipHash-1-3 function and a streaming hasher object; a hashbrown probe model), then shows that 95 deliberate faults are all caught.

- Component ID: fees (Fees and volume). The seven functions are the lookup helpers that the fee credit functions `0x3c1a250`, `0x3c1a3f0`, `0x3c1ae50` and the sibling caller `0x3c10000` call; other packets on other components stub them.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit: repository 0781ce04826eeefd89fe336cb8ea073be0c1de30 (origin/main when this was written); reference tree `references/can1357-hl` was not copied
- Claim status: observation for addresses, branches, constants, layouts and every value the evaluated bytes produce; inference for names and units; unresolved items are listed at the end
- Scope included: `0x4717440` (363 bytes), `0x47175b0` (363), `0x3ee6280` (316), `0x3ee69c0` (300), `0x3ed2180` (244), `0x3ed2280` (244) and `0x4717c50` (220), 518 instructions, each run from its real entry. The hashers run their callee `0x45927a0` as real bytes.
- Scope excluded: `0x47172c0` and `0x45927a0` (the u64 hasher and the streaming writer are the subject of the merged `RE-014-u64-key-hash-115`; `0x45927a0` only runs here as the hashers' callee and nothing is claimed about it), the vacant arm of the entry (`0x3ec8b70`, an argument-checking stub), the other helper bodies the fee credit functions call, any build or execution of the node
- Relation to node #94: none is used. The evaluator head (table decoder, strict arenas, call stubs) descends from the decoder of the author's separate fee credit distribution tool for node #115 and was extended with the SSE integer, `tzcnt`, `rol`, shift-by-`cl` and byte-store forms these functions need; every claim below was read from #115 bytes.

## Reproduce

Run from the repository root with the Python 3 standard library only. No objdump, readelf or other external program runs, and the node is never executed.

```
python3 tools/ledger_maps_115.py --out research/work-items/fees-ledger-maps-115
python3 -m unittest tests.test_ledger_maps_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
sha256sum -c research/work-items/fees-ledger-maps-115/MANIFEST.sha256
```

The first command takes about 13 s and 0.35 GB, and rewrites `evidence.json`, `instructions.tsv`, `vectors.tsv`, `controls.tsv` and `measure.json` byte for byte (two runs with different hash seeds and time zones were compared). It checks the SHA-256 of the input first, stops on any model mismatch, on an unexplained mutant survivor and on any unlisted instruction encoding. The vector list comes from a fixed-seed generator inside the tool (xorshift64*), so it never depends on the interpreter's random module. `vectors.tsv` keeps 3 of every 9 rows (index modulo 9 equal to 0, 3 or 6); `evidence.json` holds the SHA-256 of the full row text, and the tool rebuilds all 10200 rows.

Files in this folder, all written by the command above except this README and the manifest:

- `evidence.json`: subjects with FDE extents, instruction counts, the unexecuted instructions, vector groups, control counts, SHA-256 of all rows.
- `instructions.tsv`: the 518 decoded instructions with function, address, size, bytes and the tool's own decoding.
- `vectors.tsv`: the kept rows (see below).
- `controls.tsv`: every control and whether it was detected.
- `measure.json`: case and control counts (`cases`, `negative_controls`, `negative_detected`).
- `MANIFEST.sha256`: SHA-256 of each file here.

## Evidence

Coordinates are ELF virtual addresses. Function ends are FDE ends (`.eh_frame_hdr` table); the decoder must land on each end. Section lookup skips SHT_NOBITS sections.

### Subjects and who calls them (read from the bytes of `0x3c10000`, 4,750 bytes, and of the fee credit functions)

| function | extent | arguments | result |
| --- | --- | --- | --- |
| `0x4717440` hash20 | `0x4717440..0x47175ab` | `rdi`, `rsi` = hasher words k0, k1; `rdx` = pointer to a 20-byte key | `rax` = SipHash-1-3 |
| `0x47175b0` hash16 | `0x47175b0..0x471771b` | same, 16-byte key | `rax` = SipHash-1-3 |
| `0x3ee6280` find_a | `0x3ee6280..0x3ee63bc` | `rdi` = table `{ctrl, bucket_mask}`, `rsi` = hash, `rdx` = probe `{key ptr, rows ptr, row count}` | bucket pointer `ctrl - 8*index`, or 0 |
| `0x3ee69c0` find_b | `0x3ee69c0..0x3ee6aec` | same | same |
| `0x3ed2180` has_a | `0x3ed2180..0x3ed2274` | `rdi` = map `{+8 rows, +0x10 count, +0x18 ctrl, +0x20 mask}`, `rsi` = hash, `rdx` = pointer to a u64 key | `al` = 1 found, 0 not |
| `0x3ed2280` has_b | `0x3ed2280..0x3ed2374` | same | same |
| `0x4717c50` entry | `0x4717c50..0x4717d2c` | `rdi` = entry `{tag, map, bucket or hash, +0x18 key}` | row address `rows + index * 0x100` |

Call sites inside `0x3c10000` (byte scan of the function, objdump excerpt only for reading): `0x4717440` at `0x3c106ce`, `0x3c10879`, `0x3c10cb1`, `0x3c10ea6`; `0x3ee6280` at `0x3c10723`, `0x3c108c7`; `0x4717c50` at `0x3c10818`, `0x3c10922`; `0x3ee69c0` at `0x3c10cf2`, `0x3c10ee7`; `0x47172c0` at `0x3c1054d`, `0x3c105b1` with `0x3ed2180` / `0x3ed2280` at `0x3c10560`, `0x3c105c4`. The fee credit functions use `0x4717440`, `0x3ee6280` and `0x4717c50` the same way.

### Hashers: 0x4717440 and 0x47175b0

Both start by building the SipHash state: `v0 = k0 ^ 0x736f6d6570736575`, `v1 = k1 ^ 0x646f72616e646f6d`, `v2 = k0 ^ 0x6c7967656e657261`, `v3 = k1 ^ 0x7465646279746573` (the four `movabs` constants, checked by the tool in both functions), store the state in a 0x48-byte object on the stack (words in the order v0, v2, v1, v3, k0, k1, length, tail, ntail) and call `0x45927a0` with length `0x14` (hash20) or `0x10` (hash16). The finalisation is inline: `b = (length << 56) | tail`, one compression round with the message `b`, `v2 ^= 0xff`, three more rounds, result `v0 ^ v1 ^ v2 ^ v3`. That is SipHash with 1 compression round and 3 finalisation rounds; the key is the two hasher words and the key bytes are hashed without a length prefix. The reconstruction is `siphash()` (closed form) and `Hasher` (the streaming object); both are required to agree with each other and with the bytes on all 5000 hash vectors.

### Probes: 0x3ee6280, 0x3ee69c0, 0x3ed2180, 0x3ed2280

All four are the same SSE2 group probe: `tag = hash >> 57` is broadcast to 16 bytes; at `pos = hash & mask` 16 control bytes are loaded and compared; each matching byte (low bit first) gives `index = (pos + bit) & mask`; the bucket value is read at `ctrl - 8*(index+1)`; a value at or above the row count calls the bounds panic through slot `0x64df620` with Location `0x647a850`; otherwise the row key is compared; if no byte matches and any control byte is `0xff` (EMPTY) the result is a miss, else `stride += 16; pos = (pos + stride) & mask`. A DELETED byte (`0x80`) can never equal a 7-bit tag and does not end the search. They differ in the row shape:

| function | row stride | key offset | key |
| --- | --- | --- | --- |
| find_a `0x3ee6280` | `0x100` | `+0xe8` | 20 bytes, compared as 16 + 4 |
| find_b `0x3ee69c0` | `0x70` | `+0x58` | 20 bytes, compared as 16 + 4 |
| has_a `0x3ed2180` | 24 | `+8` | u64 |
| has_b `0x3ed2280` | 160 | `+0x98` | u64 |

The carry and capacity checks (`add rsi, r10; jb` and the stride of `0xfffffffffffffff0`) go to panic Locations `0x647a970`, `0x647a958` and `0x647a940` through slot `0x64df520`; they need a probe of 2^60 groups and cannot be reached by any table (the 27 unexecuted instructions are these blocks and alignment padding, listed in `evidence.json`).

### Entry: 0x4717c50

Occupied arm (tag word 0): `map = [entry+8]`, `bucket = [entry+0x10]`, `index = [bucket-8]`; `index >= [map+0x10]` calls the bounds panic with Location `0x6493b60`; the result is `[map+8] + index * 0x100`. Vacant arm (tag not 0): the function zeroes a 0xd8-byte scratch frame and calls `0x3ec8b70(out, tag, map, hash, entry+0x18, scratch)`, which hands back the map and a bucket pointer, then ends in the same bounds check and address. The tool runs this arm with an argument-checking stub for `0x3ec8b70` (tag, map, hash word and key pointer are compared) and does not claim the body of the insertion.

### Controls in detail (`controls.tsv`)

Wrong models, each run against the control vectors: SipHash with 2 compression rounds, with 2 or 4 finalisation rounds, without the length byte, with the key halves swapped, with the finalisation constant `0xfe`; a probe with an 8-bit or 6-bit tag, a linear stride, one that looks at the first group only; the same two for the u64 probes.

Byte mutants: every conditional jump, conditional move and set of the seven functions inverted, rotate and shift counts bumped by one (a third of the hasher rotations), a bit of each SipHash constant flipped, and displacements of memory operands moved by 8 bytes; 73 in all. A survivor must be proven unreached or listed with a reason; none survived (the two hash-table overflow guards need probes past the first group, which the control slice contains on purpose).

Corrupted inputs: a flipped last byte of the file and an empty input against the digest check; an address that is not an FDE start; an address outside every section; an address in `.bss`; an unlisted opcode; a truncated ULEB128; an init constant patched in the image; a patched length-byte shift and a patched tag shift in the image, caught by a one-vector self check.

### Reading `vectors.tsv`

Each row is `index, group, function, input_a, input_b, input_c, observed`. For the hashers the inputs are the two hasher words and the key bytes and `observed` is the hash. For the probes the inputs are `buckets/rows`, the hash, the query key and a 10-hex digest of the control bytes and bucket values, and `observed` is `ok:<bucket index>` (find) or `ok:<0|1>` (has) or `panic`. For the entry the inputs are the arm, `index/rows`. `index` is the position in the generated list, so the rows kept can be matched to the tool's own list. A row alone proves nothing; the proof is that the tool rebuilds every row and compares full results.

## Implementation and comparison

Not yet implemented as Rust. The behaviour is reconstructed as executable Python in the tool and compared with the evaluated bytes on every vector. This is not a build comparison, and no normalization mask exists.

- `siphash()` and `Hasher` are the two independent hash reconstructions; `RawTable` and `probe_find()` are the table reconstruction (insertion with the mirrored control tail, group probe with tag, EMPTY stop, triangular stride, bounds panic); `model_entry()` is the entry address rule.
- Tables in the vectors have 4 to 64 buckets, up to the hashbrown capacity, with identical hashes (long chains), shared tags with scattered starts, shared starts, tombstones, near-miss keys (one bit or the last byte changed), wrong hashes for present keys, and bucket values past the row count.
- Every buffer is followed by 40 bytes of non-zero garbage so that a read past a key or a length shows up.

## Results and limitations

- 10200 vectors, 0 mismatches: 3300 hash20, 1700 hash16, 1300 find_a, 1300 find_b, 1000 has_a, 1000 has_b, 600 entry (400 occupied, 200 vacant). Bounds panics are compared by Location.
- 491 of 518 instructions executed; the 27 left are the overflow panic blocks and alignment padding (see above).
- Controls, all detected: 73 byte mutants, 12 wrong models, 10 corrupted inputs; 95 of 95 (`measure.json`).
- Tests: 47 unit tests including hand-worked tables, the digest flip, decoder landing on every FDE end, tombstones, a probe that needs a second group, the panic Locations, control checks and the evidence files.
- Memory: peak resident size about 0.35 GB; the vectors run one at a time and only counters and the row digest are kept.
- Inferences, not proven: the 20-byte key is an account address, the 16-byte key is a pair of u64, the two rows (0x100 and 0x70 bytes) are the ledger rows of the fee credit functions; the binary does not name them. The hasher words are `state[0xe8]`, `state[0xf0]` in the fee credit functions (read there).
- Unresolved: the vacant-arm insertion `0x3ec8b70`, the other entry helpers (`0x4717fb0`, `0x4718060`), the two other 20-byte hashers `0x4ef4560` and `0x2b6e540` (they call a different writer), what `0x3c10000` does between the lookups. No progress gate is requested.

Next question: with these lookups real, run the sibling caller `0x3c10000` (4,750 bytes, calls `0x3c1ae50` at `0x3c10bc9`): which record does it build for the distribution and which of its two fee paths covers the spot side?
