# RE-004: unsigned perp quantity display conversion and its two failure orders

The two previously unbound perp display helpers require different zero and error ordering, and convert the unsigned quantity to binary64 before dividing, so a reconstruction can preserve both observable control flow and the intermediate rounding bits.

- Component ID: RE-004, quantities and rounding.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` is a lead only, not copied.
- Claim status: observations are the bytes, FDEs, relocation records and instruction-level control flow below; economic labels and the mathematical model's floating environment are inferences or assumptions, as marked.
- Scope included and excluded: the complete two listed FDE byte ranges, their row selection, divisor loads, success and failure branches, and binary64 result model. Existing caller bodies, the failure callees, metadata writers, admitted input ranges, other conversion functions, node #115 and runtime behavior are excluded.

## Reproduce

Run at the repository root with Python 3.12.3 and the standard library. The generator verifies the input SHA-256 before parsing, uses the shared ELF/FDE parsers, and reads the target without executing it or invoking a disassembler or subprocess. It writes only to the requested output directory. The original discovery used GNU objdump 2.42 for the human-readable excerpt below; the generator and tests do not depend on it.

```sh
python3 tools/artifacts.py verify
python3 tools/perp_display_f64_94.py --out research/work-items/RE-004-perp-display-f64-94
python3 -m unittest tests.test_perp_display_f64_94
python3 tools/catalogue.py --check
(cd research/work-items/RE-004-perp-display-f64-94 && sha256sum -c MANIFEST.sha256)
```

For repeatability, generate into two distinct scratch directories with `python3 tools/perp_display_f64_94.py --out <tmp-dir>`, vary `PYTHONHASHSEED` and `TZ`, and compare the output directories. Generation reports the input digest, FDE and full body bytes in `evidence.json`, 6 decoded conditional branches in `branches.tsv`, 6 RIP-relative data references in `references.tsv`, and the failure Locations and relevant RELATIVE relocation addends separately. `power-table.tsv` contains the 256 byte-indexed divisor words, `rounding-vectors.tsv` the exact rational rounding model, and `machine-cases.tsv` the fixed-body partial interpretation against an independent control-flow model. `branch-cases.tsv` is a compact decision table. The fixed body digests and ELF input digest prevent a silently changed instruction from being accepted; neither is itself a semantic proof.

## Evidence

Coordinates are linked ELF virtual addresses, with file offsets explicitly distinguished. FDE ranges describe unwind coverage and do not alone prove source-level function boundaries. Each listed range has an indexed FDE and the entire range is recorded byte-for-byte.

| Descriptive role | Entry VA | FDE end, exclusive | FDE VA | Body file offset | Bytes |
| --- | --- | --- | --- | --- | --- |
| price-style | `0x45a47a0` | `0x45a4838` | `0xee51d4` | `0x45a37a0` | 152 |
| size-style | `0x45a4b80` | `0x45a4c03` | `0xee52cc` | `0x45a3b80` | 131 |

Both consume a u64 raw word in `rdi`, a u64 identifier in `rsi`, and a metadata pointer in `rdx`. On the nonzero size-style path and on every price-style path, `mul` by `0x346dc5d63886594b`, followed by shifting the high 64 bits right by 11, produces `q`. The helper requires `q == metadata.+0x30`, then requires `r = id - q*10000 < metadata.+0x10`. Its selected row is `metadata.+0x08 + 48*r`, and byte `row.+0x2a` is `d`. The reciprocal is exact for **all** u64 identifiers: `10000*m - 2^75 = 432`, and `(2^64-1)*432 < 2^75`. The latter bounds the reciprocal error below the smallest distance from a nonintegral quotient to the next integer.

| Path | Conditions in execution order | Observation |
| --- | --- | --- |
| price-style | wrong quotient or `r >= length` | failure Location `l1/src/perp_meta.rs:194:38` |
| price-style | valid row, `d >= 7` | failure Location `l1/src/perp_meta.rs:319:28` |
| price-style | valid row, `d <= 6` | convert raw word, divide by table entry `6-d`, return f64 |
| size-style | raw word equals zero | return positive zero before reading metadata |
| size-style | nonzero raw and wrong quotient or `r >= length` | failure Location `l1/src/perp_meta.rs:194:38` |
| size-style | nonzero raw and valid row | convert raw word, divide by table entry `d`, return f64 |

The two failures load Location records `0x56f21c0` and `0x56f3350`, then call through distinct slots. `relocations.tsv` binds those slots to their RELATIVE addends; the bodies and effects after entering those callees are outside scope. This distinction is visible even for raw zero: the price-style function still checks the identifier and the decimal, whereas the size-style function returns before either check. A particular caller may prefilter zero; this packet makes no claim that both behaviors occur in a live invocation.

In the success path, the SSE sequence uses the bytes at `0x203e80` and `0x202ea0` to form exact low-32-bit and high-32-bit contributions, adds them with `addsd`, and then uses `divsd`. With round-to-nearest, ties-to-even and nontrapping exceptions, the mathematical result is:

```text
RN64( RN64(raw_u64) / table_bits[index] )
```

The first rounding cannot be eliminated. At raw `9007199254740993` and index 2, the model gives bits `42d47ae147ae147b`; rounding the exact rational `raw / 100` once gives `42d47ae147ae147c`. Price decimal byte 4 or size decimal byte 2 selects index 2 if the identifier and metadata are valid. These are model predictions derived from instructions, not target execution results.

The table at VA `0x6f7470` is file-backed at the same file offset. The byte index has 256 possible values; all 256 fetched qwords are positive finite binary64 values. The tool checks all entries against both independently rounded `10^d` and the successive nearest-even multiply-by-10 relation. There are 195 differences from the independently rounded powers and zero mismatches in 255 successive transitions. The first difference is index 25, `45208b2a2c280290` versus `45208b2a2c280291`. The 256 words exactly match the earlier table copy at `0x5b8f60`; the earlier `RE-004-pdi-display-decimals-94` packet already identified the recurrence and that table's discrepancy. This packet does not claim that result as new. Higher byte values are analyzed as possible machine inputs only; whether metadata can contain them is unresolved.

For a human check, the first branch of the size-style function is `test rdi,rdi; je` to a `xorps xmm0,xmm0; ret`, before its multiply and metadata loads. The price-style function instead starts with the identifier split. The generator checks the whole body bytes and decodes the six conditional displacements directly; it does not parse disassembler output.

### Inferences and relationship to prior work

The price-style and size-style names are inferred from the `6-d` versus `d` formulas and the independently mapped raw-book output path in `RE-006-raw-book-diff-output-94`. The latter already reports the two divisor formulas in its caller; here the new question is the two previously unbound entrypoint contracts, especially their distinct zero/error ordering and bit-exact unsigned conversion. The earlier caller is not analyzed in this packet. Likewise, the row-byte association is supported by the existing PDI decimal evidence, not established as a Rust type from an inferred reference name.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo build, compiler flags, binary comparison, normalization mask or target execution is claimed. The fixed-body partial interpreter reads the reciprocal, shift, conditional displacements, row guard and SSE constants from the checked ELF bytes; it simulates the selected control flow and SSE arithmetic with exact rational operations. It does not decode or execute every machine instruction. It treats metadata words as supplied inputs and stops at failure callees. The separate quotient and result models use integer division and a rational rounder. Corruption controls cover input hash, function byte, branch opcode, decimal guard, table byte, unmapped/NOBITS ranges and invalid model inputs.

## Results and limitations

The generator checks 2 indexed FDE ranges, 6 conditional branches, 256 divisor words and 255 table transitions. It compares 12,288 fixed-body interpretation cases with the separate control-flow and arithmetic model, with no mismatch; these sample raw values and identifiers and cover all 256 decimal bytes for each selected combination. It emits 3,072 rounding vectors, of which 2,162 differ from a single rounding of the exact decimal rational; this is a comparison of two mathematical models, not a differential run. The quotient bound is whole-domain; the interpretation cases are sampled. Seven focused unit tests pass, with no skips.

The current MXCSR rounding mode, exception masks, caller reachability, economic units, admitted metadata byte range, failure callee internals and full data/relocation closure remain open. The two body hashes check the exact captured bytes, not source equivalence. No node execution, Rust reconstruction, whole-node coverage or component progress gate is claimed.

Next question: determine which metadata writer and validation constrain `row.+0x2a`, then compare an independent Rust implementation under a separately authorized offline harness.
