# RE-001: node115 consensus-liner abbreviation selector

- Component: `consensus`; bounded RE-001 function and control-flow mapping, not RE-008 completion.
- Target: Linux x86-64 node115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; captured input rights and origin remain in `provenance/artifacts.json`.
- New MIT-authored interpretation. Image/export checker mechanics reuse project-authored packets #2111, #2141 and #2154; no unlicensed inferred implementation was copied.
- Status: static selector and request-level contract; no captured binary execution or emulation, no Rust or compiled-equivalence claim.

## Gap and result

The catalogue contains `node/consensus/liner.rs`, but has no digest-bound behavioral record for **`0x4ec7ff0..0x4ec8167`**. This packet authenticates that complete 375-byte body and its 19-byte slice callback. Two Location records bind the selection failures to source line 269, columns 33 and 50.

Only a byte length **at least 21** and exact lowercase **`0x`** prefix take the formatting route. The remaining characters need not be hexadecimal. For valid UTF-8, the prefix ends at the last character boundary at or before byte **6**; the suffix starts at the first boundary at or after **length − 4**. These are byte budgets, not character counts. Two `(pointer,length)` arguments and the six-byte descriptor `c0 02 2e 2e c0 00` are sent to the formatting helper. Bypass transfers the input's 24-byte owned carrier unchanged; normal formatting return is followed by a nonzero-capacity release request.

This gives reconstruction concrete threshold, case, Unicode-cut, argument-layout and ownership obligations. The `..` separator interpretation is consistent with the descriptor and two arguments, but the downstream compact-format interpreter is not recovered here. Exact emitted text, allocation and error behavior remain helper premises; the report does not present synthetic strings as captured output.

## Reproduce

From the repository root with pinned LFS inputs materialized:

```sh
python3 research/work-items/RE-001-node115-consensus-liner-abbreviation/export_disassembly.py
python3 research/work-items/RE-001-node115-consensus-liner-abbreviation/verify.py --controls
python3 research/work-items/RE-001-node115-consensus-liner-abbreviation/relations.py
python3 tests/test_node115_consensus_liner_abbreviation.py
make doctor verify test catalogue-check reproduce
```

Measured tools: Python 3.14.7, Capstone 5.0.7, GNU objdump/readelf 2.47.20260726 and LLVM objdump 18.1.4 on macOS arm64. Both native decoders start at the FDE start and stop at its exclusive end. GNU options: `-d -Mintel --insn-width=15`; LLVM: `-d --x86-asm-syntax=intel`. Readelf independently checks FDE boundaries. No instruction bytes are masked or omitted. The generic checker supports LLVM's separate LOCK prefix presentation; neither selected body contains LOCK.

The exporter regenerates native text from a temporary ELF copy. The other scripts compare fresh results with committed reports; `--write` deliberately regenerates JSON. Capstone decodes the complete owning FDE of each encoded incoming-call candidate. This finds two direct calls to the primary body and no RELATIVE slots targeting it; it does not prove all dynamic callers or runtime reachability. The shared callback's other callers are outside the census.

## Evidence

[PROOF.md](PROOF.md) gives the data flow, premises, boundary argument and unresolved contracts. The four native exports cover **394 bytes / 110 instructions**, with 375 bytes / 105 instructions constituting the primary new recovery and 19 bytes / 5 instructions callback context. `records.json` records FDEs, digests, all six call/tail-jump sites across those bodies, six relevant RELATIVE bindings, source data and incoming sites. `obligations.json` pins 13 instruction spans.

`controls.json` records **25 rejected corruptions** with whole-image, body-hash and export guards bypassed, forcing the instruction, relocation, literal or FDE obligations to catch them. `relations.json` records all 256 byte-class predicates, 16,384 code-point-width compositions, 420 Unicode endpoint/placement cases, 156 threshold/prefix cases and seven actual-byte counterfactuals. Its independent reference builds boundaries by encoding characters, rather than applying the target's signed-byte predicate. These checks support the static proof, not native differential equivalence.

`non-overlap.json` and `pr-census.json.gz` document the all-state PR audit and its limitations. The older node94 truncated-debug packet #34 has a fixed 10,000-byte cut with a failure path on a split character; it does not implement this source-bound two-sided selector. #43 maps a different `base/src/liner.rs` initializer. Historical logs containing example strings from an unlicensed reference are inventory context, not evidence for this native body.

`validation.json` and compressed logs record the required checks. No component/progress gate is changed. Raw-equal, normalized and unmatched compiled candidates are **not measured**. The next useful question is to bind this exact compact descriptor to the downstream formatter's output and failure contract, without assuming those semantics from a familiar display convention.
