# RE-004: per-user summary output scaling in node #94

This path establishes that a reconstructed summary row must retain five signed and five unsigned integer inputs through their own binary64 conversions before dividing by one million and writing ten consecutive floating-point fields.

- Component ID: RE-004 (quantities and rounding; user summary output).
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference labels are leads only.
- Claim status: observation for bytes, calls, record offsets and divisors; inference for summary and economic meanings and the numeric model; unknowns are below.
- Scope included and excluded: the three FDE extents, their direct call chain, output assembly, selected local allocation and unwind edges, divisors and the stated integer-to-binary64 model. Callee internals, units, later consumers and node #115 are excluded.

## Reproduce

Run at the repository root with Python 3.12.3 and the Python standard library. ELF sections and unwind extents are read by the repository's `tools/elf_index.py` and `tools/fde_extents.py`. The collector authenticates the input, validates byte windows, two direct-call displacements and three divisor lanes, and never executes the target or runs an external program.

```sh
python3 tools/margin_summary_scale94.py --out research/work-items/RE-004-margin-summary-scale-94
python3 -m unittest tests.test_margin_summary_scale94
```

`evidence.json` contains full bytes of the three extents, 16 fixed instruction windows, section-derived file offsets and constant bytes. `decisions.tsv` records nine conditional targets, and `fields.tsv` maps ten fields to their positions in the summary and enclosing row. `model-vectors.tsv` gives 22 inferred numeric cases, not target execution. The manifest binds these files and this README.

## Evidence

Coordinates are ELF virtual addresses. The independently parsed FDE extents, with exclusive ends, are `0x2565260..0x256533f`, `0x26b1100..0x26b142d` and `0x26b9e20..0x26ba248`. Calls at `0x25652ff` and `0x26b11fd` join the three extents. An FDE is an unwind extent and does not establish a whole-node function census.

| Stage | Observed decisions and output |
| --- | --- |
| Allocation | The first stage derives the input row count by shifting a byte difference right by six and allocates 0x138 bytes per row. A size guard or failed nonzero allocation goes to the error path. Zero-size allocation uses an empty representation. |
| Collection | The second stage skips the loop when its endpoints agree. For each row it copies the key-like bytes, calls the third stage, writes the returned 0x70-byte summary at row offset 0xa0, advances the input by 0x40 and output by 0x138, and updates the output length. Allocation failure and unwind cleanup have separate paths. |
| Summary | If the optional row argument is zero, the third stage first calls a lookup; otherwise it uses the supplied row. It calls one indirect helper in the three argument modes `(1,1)`, `(0,1)` and `(0,2)`, calls another helper, and builds the summary. Error/unwind paths are present; the internal behavior of these helpers is not claimed. |
| Scaling | Five signed and five unsigned 64-bit words flow to ten binary64 fields at summary offsets 0x18 through 0x60. The signed lanes use `cvtsi2sd`; unsigned lanes use a packed integer-to-binary64 sequence. Scalar and packed divisions use the binary64 word 1,000,000 at `0x20ae60` and its two-lane copy at `0x203b10`. |

The helper result words are identified by call order and offset, not by economic names. They map to enclosing row offsets 0xb8 through 0x100. For example, the first helper's signed word 0 reaches summary offset 0x18, its unsigned word 1 reaches 0x30, its unsigned word 2 reaches 0x20, and its signed word 3 reaches 0x28. The complete mapping is in `fields.tsv`. `0x26ba1cd` through `0x26ba1f7` performs the packed divisions and stores, while scalar stores include `0x26ba1c0`. The original conversion masks and biases are also captured in `evidence.json`. Separate packed-lane and scalar models reconstruct the low-word and high-word bias operations from those constants, then check their results against the high-level model; this is an instruction-level numeric model, not target execution. For any unsigned input `q = H * 2^32 + L`, the packed bias operations form the exactly representable terms `H * 2^32 - 2^52` and `2^52 + L`. Their sum is q and the final binary64 addition rounds that sum once. The scalar unpack sequence separately forms the exact terms `H * 2^32` and `L` before adding them. Thus the reduction to an unsigned-integer cast covers the full 64-bit domain under the stated rounding mode; the 25 tested word pairs are controls rather than the proof.

Under round-to-nearest, ties-to-even, masked floating-point exceptions and gradual underflow, the inferred value of each field is `RN64(RN64(integer) / 1000000.0)`, with the signedness in the table. Conversion precedes division. For example, unsigned 2^53 and 2^53+1 cast to the same binary64 value and therefore produce the same output; this is not exact rational division. The divisor is nonzero on this path, and all signed and unsigned 64-bit inputs have finite binary64 results after this division. The byte contracts and derived cases are static; no execution of the captured node is asserted.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lockfile, compiler flags, two-build result, binary comparison, normalization masks, helper closure and dynamic target fixtures: not yet measured. Six unit tests pass, including changed input hash, changed function bytes after rebinding the hash, changed divisor bytes, out-of-range addresses integer-width controls, a changed packed-conversion bias, and 25 combinations of high and low 32-bit boundary words. Two regeneration runs with different hash seeds and time zones are compared separately. Model cases are not target observations.

## Results and limitations

Three FDE extents, two direct calls, 16 selected byte windows, nine conditional targets, three binary64 divisor lanes and ten field destinations are recorded. No progress gate is requested. The data-flow and signedness are instruction-based; names such as margin, user, balance and currency unit are not established solely by these bytes. The summary's lookup, three indirect calls, auxiliary call, allocator and cleanup are outside semantic closure; the nine recorded branches are not a complete CFG census. The binary64 model assumes the floating-point control state stated above, which this static packet does not establish. Next question: bind the three helper return layouts and these fields to independently identified units, then compare a Rust implementation in an explicitly authorized offline harness.
