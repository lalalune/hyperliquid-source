# RE-009: reconstruct the node #115 legacy bloom filter probe, batch probe and hash-append path

This packet lets the Rust reconstruction implement, byte for byte, the 32-bit hash that seeds the filter code (`0x61c34a0`), the single-key probe (`0x612d930`), the 32-key batch probe (`0x612d7b0`) and the builder-side hash append with adjacent-duplicate suppression (`0x61365c0`) as pure functions: 10,200 cases run through the real machine code agree with an independent model in all 10,200 cases, and 54 negative controls (23 wrong models, 25 corrupted code bytes, 6 out-of-range inputs) are all detected.

- Component ID: `storage` (RE-009 storage and state roots; the filter sits in the embedded key-value store's table filter path).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository commit `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was read or copied.
- Claim status: function extents, instructions, constants and call edges are observations. The byte-level behaviour of the four bodies, as executed by the evaluator under the stated memory layouts, is an observation about the code. The names "bloom filter", "cache-local" and "hash append" are inferences from the seed `0xbc9f1d34`, the multiplier `0xc6a4a793`, the rotate-by-15 probe step and the line geometry. The grow callee `0x5e7e440` is unresolved and is replaced by a recorded stub.
- Scope included and excluded: the four functions above and their calls to each other. Excluded: the filter builder's `Finish`/space calculation, the reader constructor that fills the geometry fields, the callers of the batch probe, the grow callee body, the stack-protector failure path, and any key-value store file format.

## Reproduce

```
python3 tools/bloom_legacy_probe115.py --out research/work-items/RE-009-legacy-bloom-probe-115
python3 -m unittest tests.test_bloom_legacy_probe115
(cd research/work-items/RE-009-legacy-bloom-probe-115 && sha256sum -c MANIFEST.sha256)
```

The tool checks the input binary SHA-256 first, reads the ELF sections and `.eh_frame` through `tools/elf_index.py` and `tools/fde_extents.py`, and never runs the binary or any external program. It writes eight files; two runs into different folders are byte-identical. Peak memory is below 1 GB (the 106 MB binary is read once). Runtime is about one minute.

## Evidence

All addresses are virtual addresses of the loaded image; file offsets are not used. Extents come from `.eh_frame` FDEs and each start has exactly one FDE.

| Function | FDE start | FDE end | Bytes | Role |
|---|---|---|---|---|
| hash | `0x61c34a0` | `0x61c3525` | 133 | `hash(data=rdi, len=rsi, seed=edx) -> eax`; no calls, no stack frame |
| single | `0x612d930` | `0x612d9e4` | 180 | `may_match(self=rdi, slice=rsi) -> bool` |
| multi | `0x612d7b0` | `0x612d929` | 377 | `may_match_batch(self=rdi, n=esi, slices=rdx, out=rcx)` |
| addkey | `0x61365c0` | `0x6136645` | 133 | `add_key(self=rdi, slice=rsi)` |

Observed layout of the reader object `self` (offsets read by single and multi): `+0x08` pointer to the filter bytes, `+0x10` signed 32-bit probe count, `+0x14` unsigned 32-bit line count (the divisor), `+0x18` unsigned 32-bit log2 of the line size. Observed layout of the builder: a vector of 32-bit hashes whose begin, end and capacity-end pointers are at `+0x10`, `+0x18`, `+0x20`.

Observed behaviour (the model in the tool):

1. hash: `h = seed ^ (len * 0xc6a4a793)`; for every full 4-byte little-endian word `h = ((h + w) * 0xc6a4a793)`, then `h ^= h >> 16`; the remaining 1 to 3 bytes are added as sign-extended bytes shifted by 16, 8 and 0, then `h *= 0xc6a4a793; h ^= h >> 24`. When no tail bytes remain the function returns `h` without the final mix. All arithmetic is 32 bit.
2. single: `h = hash(key, 0xbc9f1d34)`; the line starts at `(h % lines) << log2_line`; `delta = rol32(h, 15)`; bit index `h & ((1 << (log2_line + 3)) - 1)`, tested LSB-first inside the byte; after each probe `h += delta`. The function returns true when all `probes` bits are set, and true immediately when `probes <= 0`. Both ends of the line are prefetched; prefetches have no data effect and are no-ops in the model.
3. multi: for `i < n` the first pass stores each hash and its line offset in two 32-entry stack arrays (0x80 bytes each, so `n <= 32` is a caller contract the code does not check) and prefetches; the second pass repeats the single-key probe per key and stores one byte `0/1` per key through `out`. A key's answer equals the single-key answer.
4. addkey: `h = hash(key, 0xbc9f1d34)`; when the vector is non-empty and its last entry equals `h` nothing happens; otherwise, when end equals capacity-end the grow callee `0x5e7e440` is called with (vector, end, pointer to `h`), else `h` is stored and end advances by 4. Only adjacent duplicates are suppressed.

The decoded instruction list of all four bodies is in `decoded-instructions.tsv`; every byte of every body belongs to a decoded instruction.

## Implementation and comparison

`tools/bloom_legacy_probe115.py` contains the pure-Python model (`hash32`, `single_may_match`, `multi_may_match`, `add_key`, plus the builder-side `set_bits` used only to create matching inputs) and the harness. The harness runs the real bytes with the concrete evaluator of `tools/re21_tx_admission115.py`, extended in this tool by: signed overflow flags, shift by `cl`, `div`, `bt`, `movsx` from a byte, three-operand `imul`, byte stores, `cdqe`, prefetch and `endbr64` as no-ops, and the two stack-protector sequences. The grow callee is a stub that checks its three arguments and appends the value.

Cases (all from a fixed-seed generator, so `--out` is deterministic): 1,800 hash inputs (lengths 0 to 69, including every tail class and 0x80-0xff bytes, five seed kinds), 3,600 single-key probes over filters with 1 to 101 lines, line sizes 32, 64 and 128 bytes, 0 to 24 probes and five fill densities with some keys inserted by the model, 2,400 batches of 1 to 32 keys, and 2,400 hash-append cases with vector sizes 0 to 4 and capacities 0 to 5 more than the size. The first 240 of each group are listed in the `*-cases.tsv` files; the rest are regenerated by the tool.

Negative controls (`negative-controls.tsv`): 23 wrong models (multiplier, initial fold, shift counts, zero-extended tail, mix on aligned lengths, rotate 14 and right-rotate, mask width, line shift, probe count off by one both ways, mask instead of modulo for the line, MSB-first bits, zero probes rejected, next key hashed, last batch answer inverted, no duplicate suppression, first-entry compare, any-earlier-entry compare, early grow); 25 single-byte code corruptions in the four bodies (immediates, a displacement, a register, branch senses, an opcode); and 6 out-of-range or damaged inputs (flipped binary byte, three non-function start addresses, a zero-line filter, a filter shorter than its line count). Each is detected by a fixed battery of 420 cases or by an input check.

## Results and limitations

- 10,200 cases, 0 mismatches, 0 evaluator errors; 54 negative controls, 54 detected (`measure.json`, `summary.json`).
- Probe outcomes: 26,747 true and 16,375 false answers across single and batch cases; 613 hash-append cases reach the grow callee and 483 suppress a duplicate.
- Limits: the evaluator covers only the instruction forms these bodies use and was checked only through these cases; the grow callee, its capacity policy and the batch size contract are not established; the caller that fills the reader geometry and the builder that sets bits are not identified, so the bit-setting rule in `set_bits` is an input generator, not a claim; the names are inferences.
- No component progress gate is requested.

Next question: identify the builder `Finish` (line-count and probe-count derivation from key count) and the reader constructor that fills `+0x10`/`+0x14`/`+0x18`, so the filter bytes can be produced and consumed end to end.
