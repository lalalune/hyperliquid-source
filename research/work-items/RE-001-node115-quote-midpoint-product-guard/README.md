# RE-001: node #115 quote midpoint and checked product in a row iterator

- Component: `risk`; bounded preparatory static research for RE-001.
- Base commit: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses, exclusive end addresses. Source names are captured Location/string observations, not recovered source.
- Status: measured caller instructions and data; inferred descriptive labels; helper semantics and original public types remain unresolved.
- No captured binary execution, emulation, live-node queries, signing or chain actions. No new Rust implementation or target-equivalence claim; all full-component gates stay false.

## Result

Iterator `0x294d730..0x294d8ac` advances its 72-byte row cursor before validating the row's first DWORD, which must equal1. Exhaustion writes output qword 2. An invalid row tag selects error WORD 0x62. For tag 1, the qword index at row+0x28 must be strictly below owner+0x3ae8. The quote helper receives owner+0x3ae0 + index*288 +0xa8 and returns two qwords. The helper's book/side semantics remain opaque.

If either returned qword is0, the caller selects an error path with WORD 0x196 after obtaining a diagnostic scalar through `0x46aae30`. Otherwise it computes **`(a & b) + ((a ^ b) >> 1)`**, the overflow-free unsigned floor mean. The emitted mean-zero check remains in the native record, although both nonzero inputs already imply a positive mean.

The caller next chooses the unsigned maximum of that mean and row+0x20, then multiplies by row+8 with full unsigned MUL. It rejects **either a nonzero high half or a low half greater than `0x7ffffffffffffffe`**. Therefore the accepted exact product is at most i64::MAX-1, not i64::MAX. Product 0 is allowed when quantity 0 even with an enormous selected price. Rejection selects WORD 0x6d. On success the first output qword is1, output+8 retains the index, and output+0x10 holds the product.

For error publication, the external error carrier is dropped first unless its WORD already equals 0x1a2, then the selected WORD and a path-specific DWORD are written. Output qword 0 marks the local error route, but the remaining copied words include variant-dependent register state: no fully initialized public error structure is claimed. Economic units and names are inferences only; this is a quote-pair consumer, not a complete order/risk calculation.

Prior #197 already observes the same floor-mean identity and numeric ceiling on node #94. Its notional loops classify overflow/above-ceiling values as large and its builders apply 1.03/0.97/1.2/0.8 factors and tick rounding. Those arithmetic ingredients are not new claims here. This separate node #115 iterator instead maximizes the mean against a row scalar, rejects the exact product with error 0x6d and publishes a raw tagged result. #2626 divides entry value by signed-size magnitude; it does not supply this iterator contract. The native relation uses full-range u64 boundaries and true 128-bit mathematical products to detect overflow, with changed SHR/CMOVA/SETA operands as counterfactuals. The capture is never run or emulated.

The native denominator is **1 complete FDE / 380 bytes / 103 instructions**. The four packet tests pass with 11/11 deeper corruption controls rejected, 2,500 caller-projection cases and three distinguishing counterfactuals. These counts measure static evidence and check coverage, not reconstructed implementation bytes.

## Reproduce

Run from the repository root with the pinned artifact/submodules and research LFS inputs materialized. Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM are the validation environment; exact observed versions and outcomes are in `validation.json`.

```sh
python3 research/work-items/RE-001-node115-quote-midpoint-product-guard/export_disassembly.py
python3 research/work-items/RE-001-node115-quote-midpoint-product-guard/verify.py --controls
python3 research/work-items/RE-001-node115-quote-midpoint-product-guard/relations.py
python3 -m unittest discover -s tests -p 'test_node115_quote_midpoint_product_guard.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-quote-midpoint-product-guard/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

`--write` on the verifier or relation checker regenerates the committed JSON. The export script uses GNU objdump, LLVM objdump and GNU readelf without loading or executing the target. The verifier authenticates the complete target first, binds full FDEs and their digests, compares every instruction byte/boundary in both decoders, and validates selected instruction obligations, literals, source Locations, RELATIVE call/data bindings and applicable dynamic imports. The incoming census qualifies E8 and RIP-relative FF15/FF25 forms with complete FDE decoding; it is not a census of arbitrary register/vtable dispatch.

`controls.json` deliberately bypasses whole-image, body-hash and saved-export guards to test deeper instruction/data/relocation/FDE checks. Separate tests enforce those outer guards. `relations.json` compares caller-level projections derived from native operands with independent arithmetic or ordered-event statements, including three changed-operand counterfactuals. These projections do not execute or emulate captured instructions and do not establish runtime equivalence.

## Scope and provenance

Large audit snapshots, common-file hashes and test logs are stored as deterministic `.bz2` files to keep the review diff focused. `validation.json` binds both compressed and uncompressed hashes. Read a compressed text artifact with `python3 -c 'import bz2,sys; sys.stdout.buffer.write(bz2.open(sys.argv[1], "rb").read())' <artifact.bz2>`. Native disassembly, semantic records and check code remain plain text.

`scope-check.json` records the all-state PR audit, exact address terms, related prior work and audit limits. Current main and reachable research/tool/test/doc/source history were searched as well as PR titles, bodies, file names and available patches. Related PRs: [197](https://github.com/lalalune/hyperliquid-source/pull/197), [2626](https://github.com/lalalune/hyperliquid-source/pull/2626). The result is a bounded no-overlap finding at the recorded snapshot, not a reservation against future work.

New analysis and verification code are independently authored under the repository MIT license. Generic parsing/export helpers adapt the repository's MIT research packets; no unlicensed inferred reference source was copied. Imported artifacts and reference submodules remain pinned and unchanged. `records.json` supplies the measured native denominator; there is no source-to-binary comparison, normalization mask, implementation-byte registration or completion percentage.

## Validation and remaining question

See `validation.json` and the retained logs for actual pass/fail results, environment repairs and baseline limitations. No hosted CI or container result is claimed. The next question is to recover the quote-pair helper at `0x22f6860` and identify the row scalar units with independent source and digest-bound evidence.
