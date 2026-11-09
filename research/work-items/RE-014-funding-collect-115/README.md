# RE-014: reconstruct how node #115 collects the per-asset funding premium (sequential fold 0x24e5d00 and parallel bridges 0x5b34d90 / 0x5b39440)

- Component ID: RE-014 (funding premium callers; the premium body 0x44d9060 behind `.got` slot 0x64e5f70 is the merged `RE-014-funding-premium-115`)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: workspace at 0781ce048; the evaluator engine is imported from the merged `tools/funding_premium115.py`; no #94 material is used
- Claim status: observation (byte-compared behaviour of three bodies) with inference (names, meaning of the fields) kept separate below
- Scope included and excluded: included are the 647-byte fold and the two 1,446-byte bridge bodies, run from their original bytes; excluded are the premium body itself, the rayon join `0x59ee9f0` / `0x59ef040` and the thread registry (all recording stubs), the allocator and the grow helper `0x64e4d28`, and every caller of the bridges. No progress gate is requested.

This packet makes it possible to rebuild the loop that turns a slice of asset ids into funding premium records: skip every id that is a member of a u64 B-tree set, split the rest into `id % 10000` (row index into a 0x120-byte metadata vector and a 0x60-byte oracle vector, each with its own bounds panic), call the premium body, and append a 24-byte record `(id, none flag, f64 bits)` to a vector that grows exactly when full; and, for the parallel form, the split decision and the merge of the two halves as linked lists of vector chunks, including the underflow panic, the empty list and the single-node list.

## Reproduce

From the repository root (Linux, Python 3 standard library only; the binary is never executed, no objdump or readelf output is parsed):

```
python3 tools/artifacts.py verify
python3 tools/re014_funding_collect_115.py --out research/work-items/RE-014-funding-collect-115
python3 -m unittest tests.test_re014_funding_collect_115
(cd research/work-items/RE-014-funding-collect-115 && sha256sum -c MANIFEST.sha256)
```

The tool checks the binary SHA-256 first, takes about 1.5 minutes and well under 1 GB, and writes every `.tsv`, `.json` file in this folder byte for byte. `MANIFEST.sha256` lists every other file in the folder.

## Evidence

Coordinates are virtual addresses. A byte scan of `.text` for `ff 15` rip-relative calls through `.got` slot 0x64e5f70 finds exactly three sites (`call-sites.tsv`): 0x24e5e57 inside the fold 0x24e5d00 (647 bytes) and 0x5b34f8c / 0x5b3963c inside the bridges 0x5b34d90 / 0x5b39440 (1,446 bytes each). All three are exact FDE rows. `functions.tsv` gives instruction counts and how many the cases reached (139/165 and 276/327 twice). `panic-locations.tsv` lists the Location pointers of the two bounds panics (A = metadata vector, B = oracle vector) found by the `lea rdx,[rip+d]; call *0x64df620` pattern; `bridge-calls.tsv` the first two direct calls of each bridge (thread-local worker lookup 0x5bbd780, then the join 0x59ee9f0 or 0x59ef040). `bridge-twins.tsv` compares the two bridge bodies instruction by instruction (opcode, width, condition, operands with absolute addresses reduced to a marker, branch targets relative to the function): both have 327 instructions and differ only in the join callee at offset 0x406, so every result for one bridge holds for the other.

Observed behaviour of the fold (rdi = result record, rsi = folder `(capacity, pointer, length, context)`, rdx..rcx = id slice, the context word is copied back unchanged):

1. For every id the u64 B-tree set (root at the first word, height at the second) is searched node by node over `movzx` key counts at +0x62, keys at +8, edges at +0x68; a member id is skipped without any call.
2. Otherwise `id % 10000` is computed by multiply-high with 0x346dc5d63886594b, shifted by 11, times 0x2710. It must be below the length of the metadata vector (panic A) and of the oracle vector (panic B); the metadata row is at base + 0x120 * local and the oracle word is the first word of the 0x60-byte row.
3. The premium body is called with the folder's owner and meta words. Its second result word is a tag: tag 0 stores `(id, 1, oracle)`; any other tag stores `(id, 0, first result word)`.
4. If the folder is full the grow helper runs first; then the record is written at pointer + 24 * length and the length grows by one.

The bridges add: half = total >> 1; the body splits only when half >= minimum and either the migrated flag is set (thread count is read through the worker or the global registry, split budget = max(budget >> 1, threads)) or the budget is non-zero (budget >> 1). A split with fewer ids than `half` panics with the 19-byte message at 0x93ebae. Otherwise the join closure receives the left and right slices and the merge keeps the left chain when the right is empty, takes the right chain (and frees the left chain node by node, buffer first when its capacity is non-zero, node size 0x28) when the left tail is empty, and else links left tail to right head and adds the lengths. The unsplit path runs the same loop and returns zero nodes for an empty result or one 0x28-byte node `(capacity, pointer, length)`.

## Implementation and comparison

`tools/re014_funding_collect_115.py` imports the x86-64 evaluator of the merged `tools/funding_premium115.py` and runs the real bytes of the three bodies. A separately written model (`model_fold`, `model_bridge`; no instruction decoding) predicts the outcome (final vector or panic or list) and the ordered log of stub calls (premium arguments, grow, thread lookup, join closure fields, frees, link) for every case; the set tree shape, vector lengths, oracle words (including NaN patterns), starting capacity and length, migrated flag, budgets, thread counts and chunk lists are generated deterministically. The stubs check their own arguments (rows, oracle word, closure pointers, panic message), so wrong argument wiring halts instead of passing.

`division-by-10000.tsv` reads the `movabs` magic 0x346dc5d63886594b, the `shr 11` and the `imul 0x2710` of each body as byte patterns (exactly one each) and proves `id % 10000` exact for every 64-bit id: floor(x * m / 2^75) == floor(x / 10000) holds for all x < 2^64 because 0 <= m * 10000 - 2^75 = 432 <= 2^11. `field-offsets.tsv` lists every base-register displacement the three bodies touch (71 rows) as the layout of the folder, the context, the vectors, the set nodes and the registry.

The unit tests (34, no skip) add a hand written row for each branch of the split and merge table (below minimum, empty slice, zero budget, budget halving, migrated budget with and without a worker, left-only / right-only / linked merges, left chain freed buffer first, split point beyond the slice, leaf panic) on both bridges and for the fold (deep trees, records surviving a grow, tag table, NaN oracles, empty slice, stale key).

Negative controls: six named wrong readings of the rules (skip non-members, `% 256`, grow one early, tag 1 instead of 0, inverted flag, ignore the minimum), 20 structural controls (stale oracle, changed capacity, one set member added/removed, shortened vectors, truncated slice, emptied set, changed total/minimum/budget/flag/threads for both bridges, corrupted SHA-256, interior and foreign addresses refused as function starts, flipped immediate), and 306 killed byte mutants (one edit at every reached condition, 4/32-bit immediate and structure displacement).

## Results and limitations

Observed (all in `measure.json` / `evidence.json`): 11,666 byte-vs-model runs, 0 mismatches; 338 negative controls, 338 detected (6 wrong readings, 26 structural controls, 306 killed mutants). A further 31 of 337 byte mutants survived the 160-case pool; they edit dead scratch stores and swapped or unread stack slots (the saved minimum at 0xb8, the duplicated closure slots 0x60 / 0x68, the zeroed vector copy that is rewritten before the node allocation), the initial dangling pointer 8 (unused while the capacity is zero) and the previous-link clear in the free loop whose value nothing reads afterwards. They are listed in `mutants.tsv` with `killed = 0` and are not counted as controls. The empty-vector free path of the bridge (non-empty capacity with zero records) is unreachable by construction (a vector only grows after a record is produced) and is not covered.

Inference: names (fold, bridge, folder, chunk list), that `id % 10000` splits a dex index from a local asset index, and that the join is rayon's. Unresolved: the real join bodies, who builds the id slices and the two vectors, and the callers of the bridges (the rate body slot 0x64e7898 has three larger callers 0x2bdf8f0, 0x54a9c70, 0x54b66b0, not read here). No progress gate is requested.

Next question: reconstruct the rate-body callers 0x54a9c70 / 0x54b66b0 (about 50 KB each) or the stores that consume the collected `(id, flag, f64)` records.
