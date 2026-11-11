# risk: reconstruct the node #115 asset-decimal scale family (six bodies, 10^(high-low) of one asset-meta record)

This packet lets a reimplementation reproduce, bit for bit, six small node #115 bodies that scale a 64 bit word by `10^(b49 - b48)` of one
asset-meta record: the power itself, a floor division by it, a multiply-then-floor with a fallback order, an entry lookup that multiplies a word by
it, a ceiling of `x * power / divisor` that returns 0 above u64, and the same product with a rounding flag that returns an ok word. Each rule list
is exercised against the real bytes on 24,940 cases, with 280 negative controls, all detected.

- Component ID: risk (task family RE-007 area, no gate requested)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: base `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was copied. No #94 result is used.
- Claim status: observation (byte-level behaviour of the six bodies) and inference (the meaning of the two record bytes)
- Scope included and excluded: the six bodies listed below, their panic exits and the 128 bit divide slot. Excluded: the callers other than the
  single known caller of 0x3f10820 (0x3693bd0, a 2,623 byte body not reconstructed here), the record layout above the two bytes, and the
  larger sibling copies of the same ladder (0x434f910, 0x46aa2e0, 0x3c201e0) that continue into 256 bit arithmetic.

## Reproduce

```
python3 tools/asset_decimal_scale_115.py --out research/work-items/risk-asset-decimal-scale-115
python3 -m unittest tests.test_asset_decimal_scale_115
```

The tool checks the binary digest first, reads the ELF through `tools/elf_index.py`, `tools/fde_extents.py` and the x86-64 evaluator of
`tools/bole_rate115.py`, and never runs the binary. No objdump or readelf output is parsed. Peak memory is about 0.4 GB; the run takes about
twenty seconds and writes only the files named in `MANIFEST.sha256`. The output is byte-identical across runs.

## Evidence

All addresses are ELF virtual addresses. Extents come from `.eh_frame` FDEs through the shared parser (`bodies.tsv`).

| Body | VA range | Bytes | Instructions | Role in the rule list |
| --- | --- | --- | --- | --- |
| `pow10_diff` | 0x3c4b280..0x3c4b30c | 140 | 44 | returns `10^(rec[0x19]-rec[0x18])` |
| `floor_by_diff` | 0x434f580..0x434f65c | 220 | 65 | `x / 10^(rec[idx*0x158+0x49]-rec[idx*0x158+0x48])` |
| `mul_floor_by_diff` | 0x434f660..0x434f789 | 297 | 90 | `(1, x*m/p)`; if `x*m` overflows, `(ok, (x/p)*m mod 2^64)`; index 0 skips the record, `p = 1` |
| `entry_scale` | 0x3c479c0..0x3c47ad5 | 277 | 80 | writes `(key, ok, a*b)` or `(asset, ok, b*p)` behind a flag byte |
| `ceil_scale_div` | 0x3f10820..0x3f1093e | 286 | 83 | `ceil(x*p/d)` through the 128 bit divide, 0 when the result needs 65 bits |
| `scale_div_rounded` | 0x4217e60..0x4217f8b | 299 | 91 | `(fits, floor or ceil of x*p/d)` by the low byte of the flag |

Observations (all reproduced by the tool from the bytes):

- The ladder is the same in all six: `u8 high - u8 low` (a borrow panics at Location 0x6476a48), then bit tests of the difference build
  10, 100, 10^4, 10^8 by unchecked `imul` and 10^16 (`movabs 0x2386f26fc10000`) by a checked `mul`, with an early exit once the remaining
  bits are zero. A difference of 20 or more, or any difference with bits above 0x1f, reaches the checked multiply or the final fall-through and
  panics at the same Location. So the power is defined exactly for differences 0 to 19 (`panic-locations.tsv`).
- The three panic Locations decode (from relocations) to `l1/src/spot_meta.rs` lines 1206 (ladder), 119 (vector index) and 590 (slice index):
  the family lives in the spot metadata code. That is the only naming claim.
- The element stride is 0x158 and the two bytes sit at +0x48 and +0x49 of the element; the vector is `{ptr at +0x20, len at +0x28}`. A vector index
  at or above the length panics at Location 0x64768d8 before the bytes are read, in every body except `mul_floor_by_diff` with index 0
  and `entry_scale` with the flag set.
- `entry_scale` takes the flag from the whole `cl` byte (`test cl,cl`), so a flag of 0x100 in a wider register is not set. The slice check of
  the entry index uses a different panic slot (0x64df620, Location 0x6476678) than the vector check.
- `ceil_scale_div` and `scale_div_rounded` form the 128 bit product with one `mul`, request the quotient from the divide slot 0x64dfaf8 once, and
  rebuild the remainder with `imul`, `mul`, `sub`, `sbb` to decide the +1. A zero divisor reaches the divide slot (the faulting divide belongs to
  that callee and is modelled as a fault).
- `mul_floor_by_diff` divides with `div r9d` when `(value | power) >> 32` is zero and `div r9` otherwise; the results are the same, which is why
  the `shr 0x20` immediate edits survive nowhere that matters (see below).

Raw tables: `bodies.tsv` (extents, instruction counts, reached counts, slot call sites), `constants.tsv` (ladder immediates read from bytes),
`panic-locations.tsv`, `cases-sample.tsv` (every named case and every 240th stream case with its result), `controls.tsv`, `survivors.tsv`.

## Implementation and comparison

`tools/asset_decimal_scale_115.py` holds a separately written rule list for each body (`rule_pow`, `rule_floor`, `rule_mulfloor`, `rule_entry`,
`rule_ceil`, `rule_rounded`) and a harness around the shared evaluator: a record vector, an entry table and a bare record are laid out in a
checked heap, the three panic slots and the divide slot are stubs that raise a named fault, and every case is run against the real bytes and the
rule list. A case passes only when the returned words, the written output block and the fault name agree, and nothing else in the heap changed.

Cases: 24,940 in total. 940 named cases (every ladder difference 0 to 25 for two record byte bases, the 32 bit divide threshold edges, index and
divisor faults) plus 24,000 generated with a fixed seed. Every one of the 450 instructions of the six bodies is reached.

Negative controls: 280, all detected.
- 22 wrong rule lists (ladder limits 15/16/18/20/24/31, borrow treated as zero, ceil replaced by floor, ceil wrapping instead of 0, the index 0
  shortcut checked, no fallback order, flag read as bit 0 only or as the whole word, key and other word swapped, divide checked before the
  index, floor replaced by ceiling, power off by one, slice fault reported as a vector fault, pair flag forced, rounding flag variants);
- 3 damaged inputs (an address that is not an FDE start, a foreign binary digest, one flipped code byte in the ceiling body);
- 255 edited code bytes (every reached conditional, immediate and displacement of the six bodies), each noticed by at least one case.

Seven edited bytes are not noticed and are listed with a reason in `survivors.tsv`: six are the `test dl,0x10` mask edits, equivalent because a
value that reaches that test with bit 0 set already exited through the odd-bit exits, and one is the `mov eax,0` immediate before a `setno al`. The tool
refuses to finish if any other edited byte goes unnoticed.

## Results and limitations

`measure.json`: cases 24,940; negative controls 280; detected 280; edited bytes unnoticed 7 (all explained); instructions reached 450 of 450.
Tests: `python3 -m unittest tests.test_asset_decimal_scale_115` runs 25 tests including a full rebuild comparison.

No component gate is requested and `risk` stays unchanged. Not established: the original field names of the two record bytes (they are only
shown to be a pair of u8 decimals-like values in a spot-metadata element), what the bodies' callers do with the results, and the behaviour of
the 256 bit sibling copies. The single caller of the ceiling body (0x3693bd0) additionally uses float conversion and B-tree walks; the next
question is its exact use of the `0` overflow result and the two key lookups before it.
