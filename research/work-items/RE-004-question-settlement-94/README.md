# RE-004: Question settlement fractions from input text to ordered settlement calls

This packet establishes how node #94 converts question settlement fraction inputs into an exactly-one-winner batch, including rejection order, signed-zero normalization, and the order in which settlement is called.

- Component ID: RE-004 (quantities and rounding).
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is an unlicensed source of hypotheses, not an implementation source.
- Claim status: selected byte observations and an abstract model; numerical conclusions about the SIMD window assume DAZ disabled and masked invalid-operation and denormal-operand exceptions. Inferences and open questions are identified below.
- Scope included and excluded: eight selected FDEs: row collection `0x44845b0`, `0x489edd0`, `0x4877ab0`, `0x47bbba0`; tree builder `0x4298890`; question bodies `0x4d6abc0` and `0x4d6b5a0`; and batch builder `0x486a7c0`. The two question bodies are compared in full with the explicit displacement masks below, but not every instruction is interpreted. The action handler, decimal parser, decimal-to-f64 converter, large-input sorter and settlement wrappers are external boundaries.

## Reproduce

From the repository root, using Python 3 and only the standard library plus the existing `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/question_settlement94.py --out research/work-items/RE-004-question-settlement-94
python3 -m unittest tests.test_question_settlement94
```

The target is a Linux x86-64 ELF. Verification used CPython 3.12.3 on Linux x86-64. The generator first verifies its full SHA-256, parses FDE records with the shared parser, reads only file-backed sections, and writes deterministic TSV and JSON evidence. It does not execute the target or invoke any external analysis program. For a byte-for-byte check, generate into two distinct empty output directories and compare them:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/question_settlement94.py --out "${TMPDIR:-work}/question-settlement-a"
PYTHONHASHSEED=927 TZ=Pacific/Honolulu python3 tools/question_settlement94.py --out "${TMPDIR:-work}/question-settlement-b"
diff -r "${TMPDIR:-work}/question-settlement-a" "${TMPDIR:-work}/question-settlement-b"
```

`MANIFEST.sha256` binds this README and every generated evidence file. `functions.tsv` gives hashes of the FDE-described bytes. All addresses below are ELF virtual addresses; the generated files give file offsets where relevant. FDE extents are unwind-described ranges, not a proof that no cold fragments or code outside them belong to the same logical function.

## Evidence

### From text to a fraction

A call site in the previously documented `OutcomeDeploy` handler invokes `0x44845b0` to collect the question rows and then, on collection success, calls `0x4d6abc0`. The retained bytes give the call chain:

```text
external handler
  -> 0x44845b0 -> 0x489edd0 -> 0x4877ab0 -> 0x47bbba0
                            -> 0x4298890
  -> 0x4d6abc0 -> 0x486a7c0 -> external per-outcome settlement wrapper
```

The handler is context only; its prior analysis is in `research/work-items/RE-004-outcome-deploy-action-94/README.md`. The chain and call targets, including the second body copy's two external edges, are checked in `edges.tsv`. In `0x47bbba0`, the row's outcome lookup precedes its string-length and conversion checks. The following table follows the selected normal and error edges; parser behavior itself is not reconstructed here.

| Order | Observation | Result or continuation |
|---|---|---|
| 1 | An outcome is absent from the global outcome map. | Tag `0xec`. |
| 2 | The fraction text length is above 100 bytes. | Tag `0x143`; 100 is admitted to the parser. |
| 3 | The parser's 16-bit result differs from `0x186`. | Forward the parser error. |
| 4 | The converter's low success bit is clear. | Tag `0xab`. |
| 5 | The detail text length is at least 2001 bytes. | Tag `0x143`; 2000 is admitted. |
| 6 | The checks pass. | Copy the detail and carry the converter's `xmm0` payload into the collected row. |

The two indirect calls are RIP-relative through slots `0x57731d8` and `0x5773968`; the ELF `R_X86_64_RELATIVE` records have addends `0x3799510` and `0x4ead680` respectively (`slots.tsv`). The roles text-to-Decimal and Decimal-to-f64 agree with prior evidence, but the functions behind those slots are not executed or reanalyzed. Therefore this packet does not infer which decimal strings round to binary64 0 or 1, nor the parser's complete syntax or numerical range. The calls and the error propagation around them are observations; the numerical boundary begins at the returned binary64 payload.

The generator decodes the two unsigned comparison instructions and records boundary cases in `length-cases.tsv`. The input scenarios in `input-model.tsv` are conditional on supplied parser/converter outcomes; for example, an admitted length does not establish that an empty string parses.

Before calling the tree builder `0x4298890`, `0x489edd0` uses an in-place unsigned-key insertion sort for 2 through 20 rows. Its shift condition is strict, so equal keys preserve their input order in this small-input path. At 21 rows and above it instead calls slot `0x5775038`, whose ELF relocation addend is `0x44861f0`; the callee's sort properties are not analyzed here. In the tree builder, the checked loop at `0x4298ae1` compares a current key with the next key. When both exist and match, it discards the current value's owned payload if present and continues from the next row; a different key proceeds toward insertion. Thus, for an ordered stream, an adjacent run of equal keys contributes its last row to the tree. The generator interprets that bounded branch window in `coalesce-steps.tsv`; `coalesce-model.tsv` gives conditional sequence examples. For the small-input sort, that last row is the last originally encountered equal key; no such stability claim is made for the large-input sorter. Whether duplicate keys can arise from a valid action input is unresolved. Node splits, allocation failures and the full tree-building implementation are outside this model.

### Question validation and batch construction

In `0x4d6abc0`, each collected outcome is searched in a question-associated tree before its price is compared (`0x4d6ae0d` through `0x4d6aeb0`). The error pointers and message bytes are recovered in `texts.tsv`; `branches.tsv` contains decoded branch targets. On the path with a question record and a completed collection, the selected code behaves as follows:

| Ordered condition | Observation |
|---|---|
| Outcome ID absent from the question's tree | Reject with `invalid question settlement outcome`. This test precedes the fraction test for that row. |
| Fraction compares equal to 1.0 | Retain it as the winner; a second 1.0 gives `invalid question settlement fraction`. |
| Fraction compares equal to zero | Retain it in a zero-valued row vector. Both signed zeros compare equal under the stated SIMD assumptions. |
| Any other ordered or unordered value | Reject with `question outcomes must be settled to exactly 0 or 1`. |
| No winner after the rows | Reject with `question settlement must have a winner`. This precedes the remaining-count test. |
| Number of zero rows plus one differs from the record count | Reject with `question settlement must include all remaining outcomes`. |

For these message errors the selected return path writes tag `0x17b` and byte `0x08` at result offset `+2`. A missing question lookup instead reaches a separate `0x17d` return path; this packet does not assign its complete structured error meaning. A caller may reject earlier, including at its own item-count gate.

On success, `0x4d6abc0` puts the immediate `0x3ff0000000000000` into the winner input and calls `0x486a7c0`. In the latter, the loop at `0x486a900` copies each zero-row ID and payload while explicitly writing an all-zero 64-bit fraction; it then appends the retained winner. Thus a previously accepted negative zero becomes positive zero in the per-outcome settlement call. The later loop in `0x4d6abc0` passes each resulting row to external wrapper `0x4d69ae0`; return word `0x186` continues the loop, and another word exits and forwards the wrapper result. The zero rows retain their relative collected-tree iteration order, and the winner is last. The second body has a corresponding call to batch builder `0x486a7c0` and a call to external wrapper `0x4d69820`.

### Question body comparison

The two question FDE ranges each contain 2,519 bytes. `body-raw.tsv` preserves both raw byte sequences. They differ in 78 byte positions, all inside 39 manually identified 4-byte PC-relative operands. The tool masks exactly those 156 operand bytes; the other 2,363 bytes are identical. It verifies the fixed instruction prefix at each operand and resolves both addresses directly from the bytes (`body-rel32.tsv`). Of the 39 resolved target pairs, 38 are equal. The one different pair is the per-outcome direct call: body A targets `0x4d69ae0`, body B targets `0x4d69820`. Targets of indirect calls and RIP-relative loads are slot addresses, not a proof of the runtime contents of all those slots. The three explicitly parsed relocation entries in `slots.tsv` concern the input parser, converter and large-row sorter.

This comparison supports the same branch structure and local field offsets for the two bodies modulo that boundary call; it does not prove that the external wrappers have the same effects, validate every instruction boundary, or establish source or whole-node equivalence.

**Inference:** the tree is the question's remaining outcome set and its count field represents that set's size, as suggested by the message and prior action analysis. If the collected IDs are distinct and that interpretation holds, membership plus the count equality means the batch covers the set exactly once. The packet does not prove the full tree implementation or unique-ID invariant; `model-cases.tsv` declares distinct input IDs as a precondition. The model checks validation order and reports external calls; it does not execute machine code or prove what the settlement wrapper mutates.

### Binary64 comparison domain

The shared 8-byte constant at VA `0x20a730` is little-endian `0x3ff0000000000000`. In each body, the selected window uses `ucomisd`, `jne`, and `jnp` against that constant, then clears an XMM register and uses `ucomisd`, `jne`, and `jp` against zero. The generator interprets this bounded instruction sequence and partitions binary64 encodings by sign, exponent, and whether the fraction field is zero. For these equality and unordered comparisons, each such class is homogeneous. The partition totals for each checked window are:

| Terminal | Number of 64-bit encodings |
|---|---:|
| Zero row | 2 |
| Winner row | 1 |
| Reject | 18,446,744,073,709,551,613 |
| Total | 18,446,744,073,709,551,616 |

This is an exhaustive encoding-domain argument, not an enumeration of target executions. It assumes the CPU uses IEEE binary64 comparison, the SIMD denormals-are-zero mode is disabled, and invalid-operation and denormal-operand exceptions are masked; the node's runtime MXCSR is not established here. With a different MXCSR, subnormal handling or floating-point trapping can differ. Boundary examples including both zeros, adjacent values to 1, infinities and NaNs are in `binary64-cases.tsv`. The binary64 bit patterns reaching this window from the external converter are also unproven.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No Cargo build, two-build comparison, target execution, helper closure, relocation closure, vtable/data closure, or whole-ELF equivalence has been measured. The retained relocation records identify two indirect boundary targets only. `functions.tsv` hashes the full selected FDE bytes, while `windows.tsv` and `branches.tsv` bind the particular bytes and branches used in the argument. The only normalization is the explicitly listed 39 rel32 operands in the two-body comparison; it is not a Rust comparison.

The abstract question and input models are independent explanatory specifications of selected control flow, not captured target traces. They assume the collection has produced distinct rows and that the supplied parser, converter and per-outcome results represent external calls. They do not establish side effects of unexamined helpers or values returned by the target.

## Results and limitations

- The generator checks 8 FDE extents, 36 fixed byte windows, 18 conditional branches, 11 direct calls, 3 indirect slot relocations, and 5 error-message references. The two question bodies are compared across their complete FDE ranges with 39 checked operand masks, including the one differing call target.
- For each of the two comparison windows, 8,192 symbolic classes cover all `2^64` binary64 encodings under the stated SIMD assumptions. The tool also emits 12 boundary examples and 10 length-boundary cases.
- The synthetic model reports 7 input scenarios, 4 coalescing scenarios and 9 question/batch scenarios; 6 additional cases interpret the coalescing branch window. These are not executions of the target. The focused unittest has 26 tests, including corrupt hash, instruction, branch, body bytes and targets, comparison constant address, invalid VA, ambiguous mapping, NOBITS and slot controls.
- Only the selected control-flow windows are checked. The global and question map implementations, the full parsing/conversion internals, runtime FP control, tree iteration invariant, out-of-memory/unwind paths, and the settlement wrapper and payout body remain unverified. No milestone completion gate is requested.

Next question: reconstruct the decimal-to-binary64 converter and its rounding boundaries in a non-overlapping task, then determine which textual inputs can actually reach the exact-zero and exact-one branches.
