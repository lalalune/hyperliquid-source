# RE-004: HyperEVM read precompile 0x812: gates, gas, and the rounding of its eight output words

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference has no code for this precompile.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included are the whole functions `0x324bdf0` and `0x3790f20`, with mutants. Stubs with checked arguments stand for the ABI decode `0x37e6d50`, the error formatter `0x37f3190`, the drop `0x3c1ada0`, the allocator, `memcmp`, the 128 bit divide and `Bytes` construction `0x1511380`. `0x3c02770` runs for real. The rate and utilization callees `0x37412a0`, `0x3741010`, `0x3741160` are stubs in most cases, so any word can be injected, and run for real in the rest. Excluded: the other 19 precompiles, the caller, who fills the set at `ctx +0x38`, and who writes the record.

## Reproduce

From the repository root:

```
python3 tools/reserve_read_precompile.py --out research/work-items/RE-004-reserve-read-precompile-94
python3 -m unittest tests.test_reserve_read_precompile
```

The tool takes about 90 s on a loaded server. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `constants.tsv`, `immediates.tsv`, `texts.tsv`, `holders.tsv`, `reciprocals.tsv`, `rate-word-bound.tsv`, `gas-table.tsv`, `output-map.tsv`, `rounding-samples.tsv`, `tail-pieces.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs.

| Function | Rows | Reached through | Role |
| --- | --- | --- | --- |
| `0x324bdf0` | 382 | no direct call; address held in `.data.rel.ro` slots `0x56a6af8`, `0x56dfb20` (`holders.tsv`) | whole call |
| `0x3790f20` | 40 | slot `0x5775518` | record lookup by token |

`lea` at `0x324be29` loads the 20 byte constant at `0x582610`, which is the address `0x...0812` (`constants.tsv`).

Arguments: `rdi` result, `rsi` ctx, `rdx` input with pointer `+8` and length `+0x10`, `rcx` gas limit. The result has 5 words:

| Form | Word 0, 1 | Word 2, 3, 4 |
| --- | --- | --- |
| success | `Bytes` head | word 2 length, word 3 data, word 4 gas used |
| no text | 0, 0 | word 2 = `2^63`, others untouched |
| text | 0, 0 | `String` capacity, pointer, length |

Gates, in order:

1. The address is searched in a B-tree set at `*(ctx +0x38)`: `{root, height}`, 20 byte keys from node `+8`, length `+0xe6`, edges `+0xe8`, `memcmp` through slot `0x576e488`. A hit gives the no text form.
2. Input length above 2000 gives the no text form (`cmp $0x7d0` at `0x324bec6`, `ja`).
3. `1000 + 33 * n > limit` gives the no text form (`shl 5`, `lea`, `add $0x3e8`, `jbe` at `0x324bee6`). An equal limit passes.
4. `0x37e6d50` decodes the token. A failure gives text form `Invalid input`, 13 bytes, built in place at `0x324bfc7`.
5. `token >= *(*(ctx +0x10) +0x198)` gives tag `0xea` with the token (`Invalid token`). An equal token is refused.
6. The map at `*(ctx +0x48) +0xd0` (height `+0xd8`, stride `0xb0`, keys `+0x798`, length `+0x7f2`, edges `+0x7f8`) is searched inline. A miss gives tag `0xe1` with inner byte 0 (`Borrow/Lend error: {}`).
7. `0x3790f20` then searches the same map again. A failure there gives tag `0xe1` with inner byte `0xa` (`Internal error`). Its own code, 9, is dropped. With the same tree it cannot fail after step 6, so this arm needs an injected stub.
8. Both totals are divided first. `0x37412a0` gives the rate word.
9. `0x3741010` and `0x3741160` give the utilization as a word and as a f64. Any failure of either gives tag `0xe1` with inner byte `0xa`. Their codes 1, 2, 3 are dropped.

Output: 256 bytes, eight 32 byte big endian words with 24 zero bytes in front. `output-map.tsv` comes from one probe with distinct values, so the order is read from a run:

| Word | Value |
| --- | --- |
| 0 | `r`, the result of `0x37412a0` (rate / 1e10) |
| 1 | `tail((1 - c/1e14) * (f64(i32(r)) * u))`, `c` = `*(ctx +0x48) +0xc8`, `u` = f64 of `0x3741160` |
| 2 | record `+0x18` |
| 3 | the word of `0x3741010` (ratio / 1e10) |
| 4 | record `+0x10` |
| 5 | `floor(record +8 / 1e10)` when the 32 bit word at record `+0` is 1, else 0 |
| 6 | `floor(record +0x60 * +0x78 / 1e14)`, or 0 |
| 7 | `floor(record +0x40 * +0x58 / 1e14)`, or 0 |

Rounding and width facts:

- Words 6 and 7 are 0 when the amount is 0 or when the high word of the 128 bit product is at least `1e14` (`cmp` with `0x5af3107a3fff` at `0x324c0d3`, `0x324c0fd`, then `seta`). That guard is exactly the case where the quotient has no 64 bit form. So an oversize total reads as 0, it does not saturate.
- Word 7 floors. The rate path behind word 0 ceils the same product (`0x37412a0` adds 1 on a remainder). `a = 1, ia = 1e14 + 1` gives 1 here and 2 in the rate path (`rounding-samples.tsv`).
- Word 1 starts from the already floored `r`, not from the rate, so it floors twice. Rate `19999999999` (1e14 units), `u = 0.75`, `c = 1e13` gives word 1 = 0, where one floor of the plain product gives 1.
- `cvtsi2sd %r14d` at `0x324c194` reads 32 bits as signed. `r` is at most `1844674407`, which is `302809241` below `2^31` (`rate-word-bound.tsv`), so the sign bit cannot be reached with the real callee. Injected, `r = 2^31` gives word 1 = 0 and `2^32 + 7` gives 7.
- `tail` runs over all `2^64` patterns in 13 pieces (`tail-pieces.tsv`, 1196 runs): NaN and both infinities give 0, not `u64::MAX`; a negative gives 0; finite `x >= 2^64` gives `u64::MAX`; else truncation. So `c > 1e14` gives 0 and not a negative word.
- The `/1e10` reciprocal `0xdbe6fecebdedd5bf`, shift 97, is exact for every u64 (`reciprocals.tsv`).

Gas: after the bytes exist, `total = saturating(1000 + 33*n + saturating(33*256))`, and `total > limit` gives the no text form and releases the bytes. Equal passes. The success form returns `total` in word 4, so a 32 byte call costs exactly 10504. The product and sum saturation rows are reached only by an injected output length.

`research/upstream-docs/docs/for-developers_hyperevm_interacting-with-hypercore.md` line 19 gives `2000 + 65 * (input_len + output_len)`, which is 20720 for the same call. `gas-table.tsv` lists both. The immediates are in `immediates.tsv`.

## Implementation and comparison

Not yet implemented in Rust. The tool holds a separately written rule list (`spec_run`) and an x86-64 evaluator of the real bytes. For each case it compares the whole 16 KB fixture heap, the divide requests and the event list (allocations, frees, format calls with tag and payload, drops). 267 named cases and 300 vectors match with 0 mismatches. A third of the vectors and 60 named cases run the real rate and utilization callees, using the rule list for those callees.

## Results and limitations

- All rows of both functions are reached except the 14 landing pad rows at `0x324c4f5` and later (`evidence.json`).
- 178 of 184 mutants are killed. 6 survive and each has a written reason in `mutations.tsv`. All six are equivalent edits. One is a text byte that a later store overwrites. Three are low bits with no effect at that spot. Two are clamps that the conversion after them repeats, so both clamps at `0x324c20f`, `0x324c219` are redundant.
- Mutants do not swap arithmetic operators. Vectors are samples. The whole domain proof covers `tail` only.
- `0x37412a0`, `0x3741010`, `0x3741160` are modelled, not proved here. The real runs check that the model and the bytes agree on the sampled records.
- Inference: from the docs line above, `0x812` is a read precompile, and the record is one borrow/lend token. Word meanings beyond the arithmetic are not named by any string this function reads. The no text form may mean out of gas; the same word comes from the set hit, so the caller decides, and the caller was not read.
- Inference: the docs formula may be out of date or for another network. This packet only reports that this build uses other constants.
- Unresolved: who fills the set at `ctx +0x38`, what a hit means, how the caller charges gas on the two error forms (the docs say all gas is consumed), who writes `c`, and the input `n` for real calls, which depends on the decoder.
