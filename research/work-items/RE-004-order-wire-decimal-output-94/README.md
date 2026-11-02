# RE-004: order-wire eight-place decimal output in node #94

This packet establishes how the two order-wire quantity words are reduced to canonical eight-place Decimal carriers before their `p` and `s` output fields, including the signed-limit and formatter failure paths; a reconstruction can now preserve the observed width and trailing-zero decisions instead of choosing them arbitrarily.

- Component ID: RE-004, assets and fixed-point quantities.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `abac38ba32678047d2bf9e3916cd305bdd62ffa2`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead, not implementation source.
- Claim status: observed bytes, FDE records and branch targets; arithmetic interpretation corroborated by a byte interpreter and a separately written integer model; field and type names inferred from their use and the reference. Full-domain target equivalence remains unresolved.
- Scope included and excluded: order-wire output preparation, two direct users, default Decimal digit-builder handoff and their selected failure branches. Excludes the input parser, other output call sites, writer internals, nondefault Decimal formatting, node #115 and the visor.

## Reproduce

From the repository root, using Python 3.12.3 and its standard library; no captured program, network, keys or binutils are run by the tool or tests. The node SHA-256 is checked before any evidence is produced. The shared `tools/elf_index.py` and `tools/fde_extents.py` parse file-backed sections and unwind records. Output has no timestamps or machine-specific paths.

```sh
python3 tools/order_wire_decimal_output.py --out research/work-items/RE-004-order-wire-decimal-output-94
python3 -m unittest tests.test_order_wire_decimal_output
(cd research/work-items/RE-004-order-wire-decimal-output-94 && sha256sum -c MANIFEST.sha256)
python3 tools/order_wire_decimal_output.py --out <tmp-dir-a>
python3 tools/order_wire_decimal_output.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

`evidence.json` is the only generated evidence file. It records body hashes, FDEs, selected instruction bytes and computed branch targets, constant operands, the relocation-resolved formatter, field bytes, example carriers and branch coverage. The manual instruction excerpts below aid reading; they are not input to the generator. Addresses throughout are #94 ELF virtual addresses, and ranges are half-open. File offsets below are derived from the file-backed executable section; FDE extents describe unwind ranges and are not by themselves proof of complete ownership or every possible entry.

## Evidence

| FDE start | End | File offset | Role in this packet |
| --- | --- | --- | --- |
| `0x332ee40` | `0x332f151` | `0x332de40` | output object path; prepares both words, dispatches field writers and cleanup |
| `0x332f160` | `0x332f1e6` | `0x332e160` | second consumer prepares the same two offsets and releases both strings |
| `0x3330570` | `0x3330900` | `0x332f570` | sign gate, trailing-zero reduction, Decimal carrier, formatting call |
| `0x4ead4f0` | `0x4ead671` | `0x4eac4f0` | formatting adapter selected by relocation at `0x5775970` |
| `0x4eabb90` | `0x4eac0d0` | `0x4eaab90` | Decimal digit and decimal-point builder |

At `0x332ee57` the first user loads 64-bit words at record offsets `+0x10` and `+0x18`; direct calls at `0x332ee98` and `0x332eea8` both target `0x3330570`. It copies the results into stack slots used by field writers for the one-byte keys `p` and `s`, respectively. The second user reads the same offsets and calls the converter at `0x332f174` and `0x332f181`. These facts support, but do not independently prove, the inference that the words are the order's price and size. The serializer may have further behavior outside the selected path.

At entry, `test rsi,rsi; js` sends every word with bit 63 set to the panic path at `0x33308b9`. The Location relocation used there resolves to `l1/src/order_wire.rs:326:35`; its full embedded build path is not reproduced. Zero takes a special path to a zero carrier with flags zero. For other accepted words, eight ordered tests reduce trailing zeros:

| Divisibility by 10 at the current step | Result |
| --- | --- |
| first non-divisible step `k` in 1 through 8 | retain the previous quotient and set flags to `(9-k) << 16` |
| divisible at all eight steps | retain the eighth quotient and set flags to zero |
| original word has bit 63 set | take the negative-input panic path |

The stored carrier at `0x3330812` has four 32-bit words: flags, zero, low quotient and high quotient. Inferred flags bits 16..23 are the decimal scale. An independently authored integer model divides the original word by up to eight factors of ten; no rounding occurs in this preparation. Examples in the generated file include:

| Raw word | Flags | High / low quotient | Modelled default text |
| ---: | ---: | ---: | --- |
| 0 | `0x0` | 0 / 0 | `0` |
| 1 | `0x80000` | 0 / 1 | `0.00000001` |
| 10 | `0x70000` | 0 / 1 | `0.0000001` |
| 100000000 | `0x0` | 0 / 1 | `1` |
| 123400000 | `0x30000` | 0 / 1234 | `1.234` |
| 9223372036854775807 | `0x80000` | 2147483647 / 4294967295 | `92233720368.54775807` |

The text is a model of the default digit-builder path, not a captured execution or a test of the writer. At `0x3330842` the formatting flags word is `0x60000020`; the adapter at `0x4ead4f0` derives its precision switch and passes zero precision flag to `0x4eabb90`. The latter reads the carrier limbs, builds digits in reverse by division by ten, pads with `0`, and inserts `.` at the scale. It has bounds/error paths and other format modes that are not exhaustively interpreted here. On formatter failure the converter branches at `0x3330873` to `0x3330892`; the outer output path has separate field-writer and serializer-state error exits recorded in `route_branches`.

### Arithmetic cross-check and limits

The executable-span interpreter reads instruction bytes at `0x333057b..0x3330812`, maintains x86 register widths and relevant flags, rejects unsupported operations or control-flow escapes, and stops before the output store. The body hash and byte anchors qualify the reviewed span. Against a separately expressed integer model, it produces **0 mismatches in 16,456 deterministic inputs**. All 10 conditional sites in that span have both outcomes represented, including all eight reduction decisions. This is static interpretation of selected bytes, not execution of the node and not exhaustive validation over all 64-bit words.

Several arithmetic primitives do have full-range mathematical checks. The eight high-limb multipliers and shifts are read from the code. For divisor `d`, multiplier `m`, shift `s`, and the recorded bound `N`, the generator verifies `0 <= d*m - 2^s` and `(d*m - 2^s)*N < 2^s`; this establishes the high-limb division result for all inputs up to that bound. The fifth case first shifts by five and uses divisor 3125. The low-limb multiplier is `ceil(2^64/10)` and its analogous excess bound holds for a combined limb at most `10*2^32-1`. The divisibility constant is the inverse of 5 modulo `2^64`: rotating the wrapped product right one and comparing it to `floor((2^64-1)/10)` recognizes multiples of ten. For a multiple `10q` the rotation is `q`; conversely any value passing the threshold maps back to `10q` without wrap. These lemmas do not by themselves prove every translated instruction or the entire formatter for every input.

## Implementation and comparison

Independent Rust: not yet implemented. Build, compiler/linker options, two-build comparison, normalized/raw target windows, relocation closure and behavior against an executable target: not yet implemented or measured. The Python numeric model and static instruction interpreter are research checks, not a Rust reconstruction. Nine focused unittest cases cover path identities, eight trailing-zero exits, signed boundary, decimal examples, deterministic vectors, corrupted target hash, a changed body with the identity gate separately bypassed, unsupported interpreter opcode, changed arithmetic constant, invalid address/opcode, and invalid input range. No test is skipped.

## Results and limitations

Five FDE ranges and four selected direct converter calls are qualified; this is not a function census or full-component denominator. The arithmetic interpreter checks 16,456 inputs and both outcomes of 10 branches, with zero observed model mismatches. Formatter buffer construction and writer-error routing are statically traced only, and alternate precision, allocator failures, unwinding, serializer callees, actual runtime formatting and all other callers remain open. No component gate is requested. Next question: qualify the formatter's default writer and its error propagation with a byte-driven interpreter, then independently implement and compare this path in Rust once the build provenance and execution harness are established.
