# RE-006: what does node #94 read from its books to feed the action delay samples?

- Component ID: RE-006 (book transitions)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / reference `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as a lead only
- Claim status: observation for bytes, offsets and the evaluated behaviour; inference where marked; unresolved where marked
- Scope included and excluded: included are the sampler `0x4cdf580` with its copies `0x4cdfe00` and `0x26f8d50`, the book top readers `0x3c18b70`, `0x23973d0` and `0x3c18d90`, the spot price fallback `0x32780d0` with `0x3bd5470` and `0x359ca70`, and the map use around them. The key encoder `0x3c0cea0`, the reader `0x4a07680` (the subject of `RE-006-mid-market-order-94`) and the map insert, split and drain run real but are not this packet's claim. Excluded, as stubs only, are the sample writer `0x392b930`, the status step `0x3373dc0`, the outcome lookup in slot `0x57738c8`, the allocator and the panics. The FDEs of the three copies appear as Location or caller rows in open inventories and in `RE-004-wire-asset-codec-94`. Those rows list a site; none asks what these functions compute, and that is the question here.

## Reproduce

Run from the repository root on Linux with Python 3 and the connected `artifacts/node/94/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/book_mid_sampler.py --out research/work-items/RE-006-book-mid-sampler-94
python3 -m unittest tests.test_book_mid_sampler
cd research/work-items/RE-006-book-mid-sampler-94 && sha256sum -c MANIFEST.sha256
```

The tool refuses any other binary digest. It reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no objdump or readelf output, calls no external program, and takes about 110 s on a loaded server. Its three generated files (`evidence.json`, `call_sites.tsv`, `mutations.tsv`) are byte-identical between runs.

## Evidence

Coordinates are virtual addresses. Bounds are FDE extents. File offset is VA minus 0x1000 in `.text`.

### Call path

Each copy has one direct call site, in a host with one direct caller. All rows are in `hosts` in `evidence.json`.

| Copy | Site | Host | Host's caller |
| --- | --- | --- | --- |
| `0x4cdf580` | `0x470f7a5` | `0x470e9a0` | `0x4cdf180` |
| `0x4cdfe00` | `0x47172fa` | `0x47162d0` | `0x4cdf370` |
| `0x26f8d50` | `0x222a615` | `0x22297c0` | `0x26f8b60` |

Arguments: `rdi` exchange, `rsi` a 12-byte time. No value is returned.

### Steps, first copy

1. Perp collection vector at `+0x3370`, length `+0x3378`: an empty vector panics by unwrapping error word `0x141`. Metadata vector at `+0x5c0`, length `+0x5c8`: the same. In both non-empty cases the word is built and dropped through `0x3379490`.
2. Only entry 0 of each vector is read. A run with lengths 3 and 2 gives the same events as lengths 1 and 1.
3. A u64 vector of one mid per perp book is allocated, filled and freed. Mid is `(bid & ask) + ((bid ^ ask) >> 1)`, the floored mean with no overflow, and 0 if either side is 0.
4. For each perp book at offset `i`: raw key `dex * 10000 + i`, with `dex` at metadata `+0x30`. Multiply and add overflow panic. If the mid is 0, the price is word `+0x20` of row `raw % 10000` (metadata `+0x68`, stride 0x60), bound-checked at `+0x70`. That bound panics at `l1/src/clearinghouse/oracle/oracle.rs:197:18`.
5. Map key: raw if at most 9999, raw + 100000 if at most 99899999, else `0xffffffff`. Then `raw / 10000` must equal `dex` and `raw % 10000` must be below the asset row count at metadata `+0x10`, or the path panics.
6. Price: `float(word) / 10^(6 - szDecimals)`, with szDecimals at byte `+0x2a` of the asset row (stride 0x30). Above 6 panics.
7. For each spot book in the vector at `+0x3388` (stride 0xd8): mid of its two tops. If it is 0, the fallback runs on the book named by book `+0xb0`, bound-checked at `+0x3390`.
8. The key comes from `0x3c0cea0` with flag 1. A plain spot gets `10000 + index`. A base token that the outcome lookup returns with byte 0 or 1 gets `100000000 + 10 * value + byte`, saturated, then `0xffffffff` above u32.
9. Price: `float(word) / 10^(quote weiDecimals - base szDecimals)`, bytes `+0x49` and `+0x48` of the token row (stride 0xe8). A negative difference panics.
10. Each price goes into a `BTreeMap<u32, f64>`, so the later write wins on a repeated key.
11. In key order, each entry goes to the writer at slot `0x57748d8`, which relocates to `0x392b930`: `rdi` is `+0x31b8`, `esi` the key, `rdx` the same time, `xmm0` the price.
12. The bucket is unix milliseconds, clamped at 0, divided by `+0x31d8`. `+0x31e0` is raised to it if larger. The flag "bucket above the old value" goes to `0x3373dc0`, with the text `action_delayer_log_status`, the pair 0.01 and 0.05, the network byte at `+0x8f2` and the map at `+0x3228`.

There is no zero check before the divide in step 12.

### Top readers

`0x3c18b70` and `0x23973d0` take a book at `+0x80`, the same read that `RE-006-mid-market-order-94` pins for `0x4a07680`: bid tree root, height, length, then the ask tree at `+0x98`. A null root or zero length gives 0. The walk goes down the first edge to the first leaf, climbs through the parents if that leaf is empty, and returns `abs(key)`, keeping `i64::MIN` as `1 << 63`. A hollow leaf with no key above it panics at `library/alloc/src/collections/btree/navigate.rs:534:47`.

### Spot fallback `0x32780d0`

Inputs are the two tops and word `+0x78`. The nonzero tops and that word, which is kept even when 0, are sorted. The result is the middle of three, the floored mean of two, or the one value. If that is 0, the word `+0x78` is returned. Worked example, top 7 and word 20 gives 13. Top 7 and word 0 gives 3.

### The set at metadata `+0x270`

Step 4 walks a u64 set with the raw key, and every exit jumps to the same label, `0x4cdf6f4`, with `rdi` unchanged. The walk has no effect on any output: 12 mutants in that walk survive, and each case with a halted asset matches one without. `evidence.json` and `mutations.tsv` carry each surviving row with this reason. `RE-006-halt-book-sweep-94` reads a set of the same shape at market `+0x270` and inserts into it when a perp halts. So, by inference, a halted perp with an empty book gets the row price exactly as any other.

### Copies

All three have 473 instructions and 0 shape differences. The second copy reads its fields at 10 offsets that differ from the first by `0xa80`, listed in `copy_diff`, and keeps `+0x90`, `+0x1f8` and `+0x210`. The third has the same offsets and its own callees and Locations, listed in `copies`. All three give the same results.

### Differences from the reference

`reference_claims` in `evidence.json` lists each one. The reference names `0x4CDF580` `recompute_volume_accumulator`, with a mid times size total and a book count. No size, total or count is in these bytes. Its `record_mark_price_sample_and_update_action_delay` has no caller in the reference, and these three loops are its callers on this slot.

## Implementation and comparison

Rust implementation: not yet implemented. The comparison is between a Python specification written from a reading of the bytes and a Python evaluator running the real instruction bytes. Real: the three copies, the top readers, the fallback chain, the key encoder, and the map insert, split and drain. Stubbed, with every argument recorded: the sample writer, status step, outcome lookup, result drop, allocator, memcpy, memmove and panics. Allocations are tracked, so a leak or a wrong free size fails the run.

| Metric | Value |
| --- | --- |
| Cases, each run on all three copies | 257 |
| Mismatches, all runs | 0 |
| Outcomes | no samples 54, panic alloc failed 1, panic bounds 3, panic mul overflow 1, panic panic 13, panic sub overflow 7, panic unwrap 2, some samples 176 |
| Instructions stepped | 813,577 |
| Stepped / total, three copies | 410 / 473, 410 / 473, 410 / 473 |
| Stepped / total, top reader, fallback, list, median | 118 / 124, 48 / 58, 89 / 111, 82 / 103 |
| Mutants killed / survived / unreached | 275 / 32 / 15 |
| Byte pins | 33 |

Each condition, immediate and non-stack field offset of `0x4cdf580`, `0x3c18b70`, `0x32780d0`, `0x3bd5470` and `0x359ca70` is flipped once. A mutant is killed if any case differs or crashes. Every row, with a reason where it is not killed, is in `mutations.tsv`. 32 survived and 15 were unreached. Stubs that record and run real code cannot show what a stubbed callee does.

## Results and limitations

Observed: all 257 cases match on all three copies. The outputs of the path are the map of prices in key order and the bucket flag.

Inferences, not proved here:

- The input of the delay samples is a book price, not a mark price. The reference's name says mark; the bytes give the book mean or a fallback.
- The row at metadata `+0x68` is the oracle row, by the bound Location, so the perp fallback is the oracle price. The field name of word `+0x20` is not read here.
- The word `+0x78` of the book is a price. Its writer is not read here, and whether it is a last trade price is unresolved.
- Hosts `0x470e9a0`, `0x47162d0` and `0x22297c0` are block steps. The guards in front of each site are not read.
- The vector at `+0x5c0` holds the market records of `RE-006-halt-book-sweep-94`, by its panic `clearinghouses.rs:11:29` and the shape of the set at `+0x270`.
- Only the main perp collection reaches this path, since entry 0 is the only one read. Whether entry 0 is the main dex in live state is unresolved.
- `0x3373dc0` runs its body only when the flag is 1, by the pinned `cmp bl, 1`, so the status step is a once-per-bucket event. The pair 0.01 and 0.05 is stored by that step and its use is unresolved.

Limits: all states are harness-built. No live book is known. Offset 9999 needs 10000 books, so neither side of the two key limits is run, and a raw offset of 10000 or more is read but not run. Mutants cover the first copy of the sampler and the shared fallback; the other copies run every case. The sample writer has its own logic, which this packet does not run.
