# RE-001: node115 portfolio-simulation seed and residual balances

- Component: `exchange`, with risk-related arithmetic; task **RE-001** function/control-flow mapping. This does not close RE-007 or recover the full margin algorithm.
- Target: Linux x86-64 **node115**, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes.
- Source/base revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; binary origin and rights remain those in `provenance/artifacts.json`.
- New MIT-authored static interpretation. Image/export checking was adapted from the project-authored #2111/#2141 packets. No unlicensed inferred source was used.
- Claim: one complete FDE is authenticated; selected seed and residual relations are recovered under explicit helper premises. No captured code was executed or emulated.

## Gap and result

The base catalogue lists `l1/exchange/simulate_portfolio_margin.rs` without a behavioral record for this function. This packet establishes the node115 body at **`0x2c64870..0x2c6597a`**, its source-location records, four encoded incoming calls, two seed modes, and its unsigned residual split when incoming **R9B is zero**.

The seed modes differ in provider arguments and rejected-result behavior. Both accumulate a helper-returned qword using **signed saturation**, then request a per-entry insertion. The selected residual path uses a different arithmetic domain: **unsigned multiplication by 100**, skip on overflow, absent lookup as zero, and unsigned subtraction to select a surplus or shortfall request. Equality requests zero on the surplus side; it is not skipped. These distinctions give a future reconstruction concrete tag, sign, overflow, and equality obligations.

The names `seed`, `group`, `surplus`, and `shortfall` are local inferred labels. Economic units, Rust type names, field names, and the simulation's full financial meaning remain unresolved.

## Reproduce

From the repository root, with the pinned node115 ELF materialized:

```sh
python3 research/work-items/RE-001-node115-portfolio-simulation-balances/export_disassembly.py
python3 research/work-items/RE-001-node115-portfolio-simulation-balances/verify.py --controls
python3 research/work-items/RE-001-node115-portfolio-simulation-balances/relations.py
python3 tests/test_node115_portfolio_simulation_balances.py
make doctor verify test catalogue-check reproduce
```

Native tools: GNU objdump/readelf 2.47.20260726, LLVM objdump 18.1.4; Python 3.14.7 and Capstone 5.0.7. Host: macOS arm64. GNU options are `-d -Mintel --insn-width=15`; LLVM uses `-d --x86-asm-syntax=intel`. Both start at the FDE start and stop at its exclusive end. `readelf --debug-dump=frames` independently confirms the selected unwind record. No normalization masks or disassembly truncation are used. LLVM's standalone LOCK prefix presentation is joined only to its adjacent instruction for boundary comparison.

`export_disassembly.py` replaces only the native export files. The two other scripts compare fresh results with committed JSON; `--write` deliberately regenerates their reports. Static tools read a temporary ELF copy. `verify.py` qualifies incoming E8 and RIP-relative FF15/FF25 candidates by decoding their complete owning FDEs with Capstone; this census does not establish all possible dynamic callers.

## Evidence and scope

See [PROOF.md](PROOF.md) for local data flow, helper contracts, output layout and arithmetic proof. `simulation.gnu.txt` and `simulation.llvm.txt` contain all **4362 bytes / 841 instructions**, including the excluded helper-heavy mode and unwind cleanup. `records.json` binds the body SHA-256, FDE, all 51 call sites, relevant RELATIVE relocations, source data and qualified incoming sites. `obligations.json` pins 32 instruction spans covering the claimed relations.

`controls.json` contains **48 rejected corruptions**, with whole-image, body-hash and native-export guards bypassed so that the instruction/data/relocation/FDE obligations must reject them. `relations.json` separately records mathematical boundary checks and **7 actual-byte counterfactuals** whose changed operands alter a prediction and are rejected by the target obligations. These are static deductions, not differential execution, helper emulation, or evidence of runtime reachability.

`non-overlap.json` and its compressed PR census record the all-state audit, including older overlapping subject areas, search limitations and an explicit distinction from the two earlier portfolio-margin admission packets. `validation.json` records exact validation scope and results.

## Limits and next question

Valid memory/container invariants and normal helper returns are premises. In particular, the signed saturation result describes the path **if** `0x4524e40` returns; its overflow reporting or panic policy is not recovered. The per-entry, grouped, split and update helpers are address-bound, not implemented or financially interpreted. No zero-initialization or duplicate-key semantics is assumed for their internals. The R9B-nonzero path invokes additional state-transforming helpers and is exported for context, not reconstructed here. A second source-bound specialization at `0x55e3770` is a lead, not an equivalence claim.

No Rust reconstruction or compiled-code comparison is submitted: raw-equal/normalized/unmatched compiled candidates are **not measured**, and no selected-byte or component completion credit is requested. All acceptance gates remain unchanged. The next useful question is the contract of `0x3f10c10`: how the grouped seed collection and transformed input produce the two collections consumed by the residual stage, including units and ordering.
