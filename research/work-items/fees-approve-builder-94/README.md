# fees: the approveBuilderFee path in node #94

- Component ID: `fees` (first task: maker/taker fee formulas and time-window rollover; this packet fixes who may be approved as a builder
  and which text becomes a maximum builder fee, the limit a builder fee is later checked against).
- Target release and full SHA-256: hl-node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` /
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only, nothing copied).
- Claim status: observation for bytes, decoded instructions, evaluated outcomes and status texts; inference where marked; unresolved
  items are listed at the end.
- Scope included: the user entry `0x1e60a90`, the system entry `0x1e64620`, the text parser `0x3364cd0`, the text-to-Decimal wrapper
  `0x3799510`, the gate `0x2758330` and the writer `0x37459e0` in full. Run as real dependencies, with no new claim: the Decimal scale
  `0x3750350` and its multiply and fraction helpers, the Decimal text parser `0x4eacd00` family, the f64 text parser `0x15756d0`
  family, the f64 to Decimal step `0x4eac740`, the table entry path `0x3596da0` and `0x379a610`, the map insert `0x339df50` and remove
  `0x33aacd0` families. Scope excluded: the book lookup `0x36f57f0`, the margin summary `0x37d79e0`, the hash `0x399c7a0`, the table
  reserve `0x357d310`, the drops `0x3379490` and `0x3762510`, and allocation (all stubs); readers of the approved map; the other
  parser caller family `0x23e7d10`; node #115.

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 tools/fees_approve_builder.py --out research/work-items/fees-approve-builder-94
python3 -m unittest tests.test_fees_approve_builder
(cd research/work-items/fees-approve-builder-94 && sha256sum -c MANIFEST.sha256)
# optional, for a human reader only; no evidence file uses this
objdump -d -M intel --start-address=0x2758330 --stop-address=0x275849a artifacts/node/94/hl-node
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input SHA-256 first and
fails on any other file. It starts no external program, so no binutils version can change its output. Sections and FDEs come from
`tools/elf_index.py` and `tools/fde_extents.py`. It does not run the node or visor: decoded instructions are interpreted in
Python, on memory built by the tool. A run took about 105 s on 4 workers.

Outputs: `evidence.json`, `vectors.tsv`, `mutations.tsv`, `instructions.tsv`, `reference-diff.tsv`.

## Evidence

Coordinates are ELF virtual addresses. Every range is an `.eh_frame` FDE, and the table decoder must land on each FDE end.

Function | Range | Instructions | Executed
--- | --- | --- | ---
user entry | `0x1e60a90..0x1e60ba5` | 74 | 74
system entry | `0x1e64620..0x1e646be` | 41 | 41
gate | `0x2758330..0x275849a` | 85 | 78
text parser | `0x3364cd0..0x3364ec6` | 99 | 99
writer | `0x37459e0..0x3745a5b` | 37 | 37
text to Decimal | `0x3799510..0x3799703` | 126 | 112

Unexecuted instructions are listed in `evidence.json` with reasons, and the tool fails on any other: `0x37996d8..0x3799703` (unwind landing pad of the f64 path: needs a panic inside the Decimal conversion); `0x275847d..0x275849a` (ud2 after the unwrap panic, unwind landing pad and the trap after it).

Observed order, user entry `0x1e60a90` (action: text pointer `+0x8`, length `+0x10`, builder address `+0x40..+0x54`):

1. Length at or above `0x65` gives status `0x143` "Invalid input length". The word at output `+0x10` is the action pointer. This test is
   in the entry, not the parser.
2. Parser `0x3364cd0` (slot `0x5773168`): the last byte must be `0x25`, then the text before it goes to `0x3799510`, then `0x3750350`
   with mode 0 and 3 digits. Every parser failure is status `0x12a` "Percentage is invalid."
3. Gate `0x2758330`, then outer tag 13 for success, 14 for an error.

System entry `0x1e64620` (fee `+0`, builder `+0x8`): a fee at or above `0x0ccccccccccccccc` gives `0x13f` "Invalid input number" with
the fee as word, before the gate. There is no text and no other limit.

Gate `0x2758330`(out, exchange, user, builder, fee), for a non-zero fee only:

- The word at exchange `+0x5c8` must not be 0. Otherwise a value holding `0x141` "Invalid perp DEX" reaches `Result::unwrap`, a panic.
- `0x36f57f0` looks up the **builder** address: `rcx` is saved in `r14` at `0x2758341`, and the 20 bytes copied to `[rsp+0x70]` at
  `0x275837f` are its target. The user argument (`r12`) is not used until the writer.
- `0x37d79e0` (slot `0x5773178`) gets `edx = 1`, `ecx = 1`. The first output word is compared with `99999999` with a signed `jg`.
  At or below that gives `0x127` "Builder has insufficient balance to be approved." Vectors: 100000000 passes, 99999999 and any negative
  value fail.

Writer `0x37459e0` (slot `0x5774d30`, tracker = exchange `+0x5d0`, table = tracker `+0xc0`): `0x3596da0` gets or creates the user row
first. Fee 0 removes the builder, and removing an absent one succeeds, so it can leave a new empty row. Otherwise a map
length (value `+0x90`) above 10 gives `0x12b` "Too many builders approved. Remove a builder by calling approve with max fee of 0.",
and this also refuses an overwrite of a builder already present. The map root is value `+0x80`, its height `+0x88`. The map holds at most
11 entries, and the evaluated tree stayed one leaf: values at node `+0x8`, 20-byte keys at node `+0x60`, length `u16` at node `+0x13e`.

Text outcomes. `path` says which path gave the value; `reference` is the rule in `handlers/54_approve_builder_fee.rs`.

Text | Status | Millis | Path | Reference rule
--- | --- | --- | --- | ---
`1%` | `0x186` | 1000 | decimal | 1000
`+1%` | `0x186` | 1000 | decimal | refused
`-0%` | `0x186` | 0 | decimal | refused
`1_0%` | `0x186` | 10000 | decimal | refused
`.5%` | `0x186` | 500 | decimal | 500
`5.%` | `0x186` | 5000 | decimal | 5000
`0.0010%` | `0x186` | 1 | decimal | refused
`0.0001%` | `0x12a` |  | decimal | refused
`1e-3%` | `0x186` | 1 | float | refused
`1E2%` | `0x186` | 100000 | float | refused
`0.1e-2%` | `0x186` | 1 | float | refused
`0.29e-2%` | `0x12a` |  | float | refused
`1.00000000000000000000000000049%` | `0x186` | 1000 | float | refused
`9223372036854775.806%` | `0x186` | 9223372036854775806 | decimal | 9223372036854775806
`9223372036854775.807%` | `0x12a` |  | decimal | 9223372036854775807
`inf%` | `0x12a` |  | none | refused
`-1%` | `0x12a` |  | decimal | refused

The rules, all evaluated from bytes:

- The Decimal path takes an optional sign, then a digit or a point followed by a digit. After that it takes digits, one point and `_` anywhere. More
  than 28 places, or a mantissa of `2^96` or more, fails this path. It does not round.
- A text that fails there goes to the f64 parser. So exponents work, and long fractions round through f64:
  `1.00000000000000000000000000049%` gives exactly 1000. `inf` and `nan` are refused by the wrapper's exponent test.
- The value is scaled by 10^3 and must be whole, non-negative, at most `2^63 - 2`. A minus sign is refused only for a non-zero value, so `-0%`
  means fee 0, which removes the builder. The largest rate through the user entry is `9223372036854775.806%`, about ten times the system limit.

Copies, instruction by instruction after rip targets are made absolute:

Function | Copy | Differences
--- | --- | ---
`0x2758330` | `0x4d80fb0` | 0
`0x2758330` | `0x4d81120` | 3
`0x1e60a90` | `0x46bba70` | 1
`0x1e60a90` | `0x46bbb90` | 1
`0x1e64620` | `0x4c03940` | 1
`0x1e64620` | `0x4c039e0` | 1

`0x4d81120` shifts exchange `+0x5c0`, `+0x5c8` and `+0x5d0` to `+0x1040`, `+0x1048` and `+0x1050`, the same shape as the third
copy in the open start trial packet. The parser slot has other callers in the family `0x23e7d10`, `0x4ad78b0`, `0x4ad81e0`, which is outside this packet.

Reference comparison is in `reference-diff.tsv`. The rule differences over the text vectors, counted by the tool:

Kind | Vectors | First text | Bytes | Reference rule
--- | --- | --- | --- | ---
exponent | 253 | `1e1%` | 10000 | refused
minus sign with zero value | 9 | `-0%` | 0 | refused
more than 28 places, f64 fallback | 8 | `1.00000000000000000000000000000%` | 1000 | refused
more than 3 places with zero tail | 40 | `0.0000%` | 0 | refused
other | 2 | `9223372036854775.807%` | refused | 9223372036854775807
plus sign | 18 | `+0%` | 0 | refused
underscore | 87 | `1_0%` | 10000 | refused

## Inferences

Kept apart from the above.

- The gate means the builder must hold at least 100 USDC in account value, reading the first summary word as account value in units
  of 1e-6. Basis: the status text says the builder's balance, the lookup key is the builder address, and the limit is 1e8. The summary
  is a stub, so the meaning of that word is from the reference label only.
- Millis are thousandths of one percent, so `1%` = 1000. Basis: the text suffix and the digit count 3.
- `0x4eacd00` is `rust_decimal` strict text parsing, `0x4eac740` its f64 conversion, `0x15756d0` the standard f64 text parser. Basis: the
  behaviour in the vectors. No symbol names them.
- The tail of the error chain carries no extra meaning: `0xa8` and `0xac` are replaced by `0x12a` with their other bytes kept, as the copy
  cases show.

## Implementation and comparison

Rust implementation: not yet implemented. Comparison is between the evaluator and a separate closed-form Python model in
the tool (`decimal_text`, `float_shape`, `from_f64`, `parse_model`, `World`), with the output, the table rows, the map leaf and the
exchange bytes compared after every step. A byte comparison with a rebuilt binary is not yet measured.

- Vectors: 3059, mismatches 0. Groups: cap 4, copy 6, curated 149, digits 500, exponent 500, gate 8, limit 5, long 300, no-dex 6, random 80, shape 1500, text 1. Text outcomes: 0x12a 1956, 0x186 993. Text paths: decimal 930, float 795, none 1224.
- Copy cases: a stub callee writes an error with a different byte at each offset, and the caller must pass all 96 bytes at the fixed shift,
  and pass the same bytes to the drop.
- Mutants: every conditional, field offset and immediate of the six subject functions. 266 mutants, 250 killed, 16
  equivalent, each with a reason in `mutations.tsv`. The survey ran 427 vectors, then all vectors for any survivor not listed as equivalent, so the listed ones were tried on the survey vectors.
- Stubs refuse wrong arguments: the book lookup checks the base and the address, the summary checks all flags and the base, drops check
  the status, and table growth is a fault.

## Results and limitations

No progress gate is requested. Unit tests: 38 passed.

Unresolved or limited:

- `r8` at the call of `0x37d79e0` is not set by the gate. `0x37d79e0` stores `r8d`, and the value left by `0x36f57f0` is a probe offset
  in the path seen by inspection. What that argument means was not resolved.
- The summary and book lookup are stubs, so a builder without a user row and the meaning of the summary flags are not covered.
- Helpers were run, not surveyed: mutants only touch the six subject functions, and 3278 of 7292 helper instructions executed.
  `0x3750350` has its own open packet (#94). This packet only uses mode 0 with 3 digits.
- The f64 model uses Python's `float`, which is correctly rounded like the evaluated parser on all vectors here, not a proof for every text.
- The evaluated map path is one leaf. The tree split code was decoded but not reached, and no vector can reach it through this
  path because the length stops at 11. A larger map from another writer is not covered.
- Whether the map is read with the same units at order time is not covered.

Next question: which function reads the map at value `+0x80` when an order carries a builder fee, and how does it compare the order's
tenths of a basis point with these millis?
