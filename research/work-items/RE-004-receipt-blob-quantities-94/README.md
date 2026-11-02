# RE-004: receipt blob quantity and price construction in node 94

This packet establishes how the receipt path combines an optional blob price, a checked blob-gas quantity, and a cumulative-gas difference, so a reconstruction can preserve their separate presence flags, widths, rounding, and failure order.

- Component ID: RE-004, quantities and rounding.
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` is an unlicensed lead, not copied implementation.
- Claim status: observations are the FDEs, instructions, relocations, data, source-location suffixes and selected branch destinations; the business names and the unsigned-division helper contract are inferences. Unresolved items are stated below.
- Scope included and excluded: the selected receipt-related quantity path of FDEs `0x26b79b0..0x26b7e66` and `0x4e5b5b0..0x4e5c144`, their connection, arithmetic loop, output packing and selected failure branches. The receipt decoder, other serializer fields, error-handler bodies, complete iterator semantics, other fee calculations, node #115 and all target execution are excluded. FDEs describe unwind ranges and are not a complete function census.

## Reproduce

From the repository root, with Python 3.12 and the standard library:

```sh
python3 tools/artifacts.py verify
python3 tools/receipt_blob_quantities94.py --out research/work-items/RE-004-receipt-blob-quantities-94
python3 -m unittest tests.test_receipt_blob_quantities94
python3 tools/catalogue.py --check
(cd research/work-items/RE-004-receipt-blob-quantities-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC0 python3 tools/receipt_blob_quantities94.py --out work/receipt-blob-check-a
PYTHONHASHSEED=2 TZ=Pacific/Honolulu python3 tools/receipt_blob_quantities94.py --out work/receipt-blob-check-b
diff -r work/receipt-blob-check-a work/receipt-blob-check-b
```

The generator checks the input SHA-256 before parsing; it imports the repository ELF and FDE parsers, excludes file-unbacked sections and invokes no external program. It does not execute the target. `functions.tsv` retains the two complete FDE-range byte strings, file offsets, FDE records and hashes; `windows.tsv` and `branches.tsv` retain selected instruction bytes and decoded branch destinations; `layout.tsv` extracts offsets and the previous-row stride from bytes. `evidence.json` records the two call-slot relocations used by the slice, the caller relocation, constants, source-location suffixes and counts. `series.tsv`, `walk-cases.tsv`, `walk-sites.tsv`, `ranges.tsv`, `rounding-witness.tsv`, `packing.tsv`, `cases.tsv`, `tag-decisions.tsv`, `tag-bits.tsv`, `gate-coverage.tsv` and `caller-cases.tsv` are generated arithmetic and gate results. The analysis completed without a timeout and is limited to these ranges and selected slices.

## Evidence

All addresses are linked ELF virtual addresses; their file offsets are generated in `functions.tsv` and `windows.tsv`. Slot `0x5774700`, called at `0x26b7b22`, has the RELATIVE relocation target `0x4e5b5b0`. The caller copies the two-word context at its own state pointer `+0x60` into the callee context `+0x10`; the first byte and the second word of that context feed the optional calculation. This connection is an observation, not a claim about who creates that context.

The caller first checks the first iterator. It advances that iterator by `0x150` before comparing the row's first 16 bytes with a constant containing 5. The matching sentinel returns before consuming the second iterator. If the second iterator is empty, the first was already advanced and the second is not. Otherwise the second advances by `0x28` and the caller invokes the receipt builder. After the call, the caller checks its counter against `u64::MAX` before incrementing it; that failure is after the call, not a guard before it. `caller-cases.tsv` records all Boolean presence/sentinel combinations at zero and maximum counter. These are a model of the pinned local branches, not a claim that all combinations occur in node state.

### Receipt gates and output fields

The following table describes the selected path, in instruction order. `index` comes from callee context `+0x40`, and `current` from the receipt row `+0x18`. The previous rows have stride `0x28` and their cumulative word is at `+0x18`.

| Gate | Observed result on the selected path |
| --- | --- |
| Decoder result byte differs from 1 | Return a record whose first word is 2, before the quantity checks. |
| `index == 0` | Delta is `current`. |
| `index > 0`, but `index - 1` is outside the previous-row count | Delta is 0. |
| Previous row exists | Delta is `current - previous[index - 1]`; unsigned underflow takes the failure at `0x4e5b67f`. |
| Transaction's first 16 bytes differ from the 16-byte constant whose low word is 3 | The blob-gas and blob-price presence words are both 0. |
| Transaction tag matches 3 | Read its word at `+0xc0`; if any bit at or above bit 47 is set, take the failure at `0x4e5c0d5`. Otherwise blob-gas presence is 1 and amount is that word shifted left 17 bits. |
| Blob tag matches, context `+0x10` byte is 0 | Blob-gas remains present; blob-price presence is 0. |
| Blob tag matches, context `+0x10` byte is nonzero | Read the u64 at context `+0x18`, run the checked price loop and set blob-price presence to 1 if it succeeds. |

On the successful builder path, output `+0` is the price presence word, `+0x10` and `+0x18` hold its low and high 64-bit limbs, `+0x40` is gas presence, `+0x48` is the gas word and `+0x1e8` is the delta. Payloads behind absent options are not claimed. The two price limbs are packed through byte-shifted stack words before their final stores. `packing.tsv` covers zero, all 128 individual input bits, and all bits set. The shifts and ORs put each bit into a disjoint position, so this basis establishes the packing identity for every 128-bit word, conditional on the pinned slice and ordinary x86 bit semantics.

The count guard is exact for every u64: the largest passing count is 140737488355327 and its gas quantity is 18446744073709420544; the next count fails before any shift result is used. The non-blob branch does not read or check this count. A delta underflow precedes both the blob count and price checks. `cases.tsv` includes controls for all of these orderings.

### Price arithmetic

The three independent immediates used in this builder's selected loop are 3338477. Assuming the callee at slot `0x576e1a8` returns an unsigned 128-bit floor quotient, its observed multiply, carry, branch and division sequence has this rule for excess `x`:

```text
d = 3338477
sum = 0; term = d; i = 1
repeat:
    sum = checked_u128_add(sum, term)
    numerator = checked_u128_mul(term, x)
    divisor = checked_u128_mul(i, d)
    term = floor(numerator / divisor)
    i += 1
until numerator < divisor
price = floor(sum / d)
```

Each addition and multiplication has its own failure destination in `branches.tsv`. A division is requested even on the final iteration, where it yields zero. The loop computes a floor for every term. For `x = 0` the modeled price is 1; for `x = 3338477` it is 2. At `x = 100000000` the byte walk gives 10203769476395, while an ideal exponential with only one final floor gives 10203769478520, a difference of 2125. `rounding-witness.tsv` contains exact rational lower and upper bounds for the ideal value: the first 160 nonnegative Taylor terms are a lower bound and the remaining terms are bounded by a geometric series whose ratio is `x / (d * 161)`. Both bound floors agree. This establishes the mathematical comparison, conditional on the modeled division hook. The selected receipt loop contains the fixed denominator above. A separately proposed version-dependent fee calculation is a different path; this packet does not establish that both paths receive the same excess or that a particular version reaches this receipt builder.

For this fixed denominator, the wide model's last successful u64 input is 192204552, producing 10079293834132079738693097 in 168 iterations. The next input reaches the checked term-product failure in 58 iterations. `ranges.tsv` records the resulting model intervals. This is conditional on the lifted loop and the division contract: nonnegative terms and their partial sums are monotone in `x`, so once a checked intermediate fails, a larger input must fail no later than that same check or an earlier one. This argument covers the modeled u64 domain; it is not exhaustive execution of the binary.

The source-location suffixes in `evidence.json` point to transaction, receipt and EIP-4844 files. Together with the tag, shift and use of the fixed divisor they support the names blob count, gas and price; the byte sequence alone does not prove field ownership or reachable chain inputs. No reference-source name is used as evidence.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Build flags, two-build comparisons, normalized comparisons, helper/data closure and binary equivalence: not yet measured. The byte walker interprets the actual instructions from the loop entry through its final branch and checks the division slot relocation; it replaces that helper with mathematical unsigned division and separately models the last division. The alternative wide model uses independent arbitrary-precision expressions. A separate branch walker decodes the selected receipt conditional jumps from bytes and supplies modeled flags and data; it reaches both edges of all 7 selected receipt branches. The caller gates, record loads, packing and output writes are static lifts, not a full instruction walk. No captured node or visor was executed.

Negative controls include an incorrect artifact digest, an altered immediate and branch with recomputed artifact and function hashes, an altered tag constant with a recomputed artifact hash, a changed but valid instruction that alters the walked result, an unknown instruction, a missing relocation, duplicated or missing selected FDE, an unbacked address, NOBITS storage, arithmetic boundaries, and absent/present options.

## Results and limitations

- 2 FDE ranges, 13 selected byte windows, 15 selected branch destinations, 16 decoded layout rows and 3 relocated calls are retained.
- 267 excess inputs agree between limb and wide models. The byte walker independently agrees with the wide model on 75 selected inputs, visiting 44 distinct instruction sites. The division helper is a modeled edge, and site count is not full-function coverage.
- 130 packing vectors cover the 128 one-bit inputs plus zero and all bits set. There are 13 receipt gate fixtures, 16 caller gate fixtures, 512 tag-byte decisions and 4 mathematical range rows. The branch walker and receipt model agree on every fixture and on every decoder and excess-presence byte separately; 129 full-width tag controls include one flip of each bit; the controlled cases cover 14 edges of 7 selected receipt branches.
- 28 focused unit tests pass without skips. The artifact verifier and catalogue check pass. Independent regeneration under different hash seeds and time zones is byte-identical.

The price-loop proof assumes unsigned floor division and the pinned instruction interpretation. The complete decoder, transaction/receipt type invariants, actual reachability of the tag-3 transaction and input ranges, uninspected fields, allocation and error handlers, and how the output is later serialized are unresolved. The instruction walker covers only the arithmetic loop; the branch walker interprets selected conditional jumps with modeled data and flags. No full-scope milestone gate is requested.

Next question: trace a non-overlapping producer of the two-word context and establish whether its excess payload and version policy are the same as those used by the independent block-fee path.
