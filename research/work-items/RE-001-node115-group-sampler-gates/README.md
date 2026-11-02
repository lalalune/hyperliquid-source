# RE-001: node115 group-sampler pairs and collection gates

- Component: `node-runtime`; bounded RE-001 control-flow and layout research.
- Target: Linux x86-64 node115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; captured input provenance and rights remain in `provenance/artifacts.json`.
- Independently authored MIT interpretation; image/export mechanics reuse the project-authored #2111/#2141/#2154/#2184 packets. No unlicensed inferred implementation was copied.
- Status: static request-level relations under explicit helper and memory premises; no captured execution/emulation, reconstructed Rust or compiled-equivalence claim.

## Gap and result

The catalogue lists `node/group_and_seq_sampler.rs` without a behavioral record for **`0x5b298d0..0x5b2a121`**. This packet authenticates the complete **2129-byte / 500-instruction** FDE and resolves its flat record scan, grouped pair append and two collection gates. A source Location binds the sample-recording call to line 169, column 10.

The flat representation scans 616-byte records through at most two contiguous spans. For each record, a u32 at `+0x248` is passed as the group lookup key; the returned vector receives the pair `(qword +0x208, qword +0)`, in that order. Grouping and sequence labels are inferred from the source and data flow; lookup/default/duplicate-key behavior is still a helper contract.

After the outer helper's nonzero-byte admission, one collection request occurs when the first observed group count is **at least 3**. A second, separate request occurs when the later count is **at least 2** and a provider-returned u32 satisfies **`word >= 360`**. The latter result is proved over all **2^32** inputs from three native reciprocal products: their combined expression is exactly `floor(word/60)`, compared against 6. The two calls are not alternatives. With an unchanged count of 3 and word 360, both execute. The word comes from a separate provider, not the elapsed-sample temporary; this does not establish a 360-second interval since the previous sample.

Both requests target `0x5b70cf0`, and their returned buffers are released if their capacity is nonzero. This packet establishes requests and local effects, not emitted logs, collection contents, allocator behavior or scheduling.

## Reproduce

From the repository root with pinned LFS inputs materialized:

```sh
python3 research/work-items/RE-001-node115-group-sampler-gates/export_disassembly.py
python3 research/work-items/RE-001-node115-group-sampler-gates/verify.py --controls
python3 research/work-items/RE-001-node115-group-sampler-gates/relations.py
python3 tests/test_node115_group_sampler_gates.py
make doctor verify test catalogue-check reproduce
```

Tools: Python 3.14.7, Capstone 5.0.7, GNU objdump/readelf 2.47.20260726, LLVM objdump 18.1.4, macOS arm64. Native decoders start at the FDE start and stop at its exclusive end. GNU options: `-d -Mintel --insn-width=15`; LLVM: `-d --x86-asm-syntax=intel`; readelf: `--debug-dump=frames`. No selected instruction bytes are omitted or masked. The inherited checker supports LLVM's separate LOCK-prefix presentation; this body contains no LOCK.

The exporter reads a temporary ELF copy and replaces only its disassembly/FDE exports. Other scripts compare fresh results with committed JSON; `--write` deliberately regenerates reports. Incoming E8/FF15/FF25 candidates are qualified by decoding their complete owning FDEs with Capstone. There are 18 E8 calls in one enclosing caller and no RELATIVE slots targeting the selected entry. This is not a census of arbitrary dynamic calls or proof of runtime reachability.

## Evidence and validation

[PROOF.md](PROOF.md) separates native observations, mathematical deductions and unresolved contracts. `records.json` authenticates the complete body, all 28 calls, six relevant RELATIVE bindings, source data and incoming sites. `obligations.json` pins 18 selected instruction spans. Full exports retain the excluded duration conversion, alternate container paths and cleanup context.

`controls.json` contains **27 rejected corruptions** with image/body/export guards bypassed. `relations.json` records three interval proofs covering all u32 inputs, 4,414 independent word checks, 45,920 flat-span cases against a modulo-index reference, 53,760 independent gate cases, a record-layout witness and **eight actual-byte counterfactuals**. These are static deductions, not target execution or a claim that finite examples establish full sampler equivalence.

`non-overlap.json` and the compressed PR census cover all PR states and main history. The closest path mention is #762, a node94 body inventory with no computation claim, closed by the maintainer for an unimportable test. #1789 studies ABCI sample handoff and line serialization; #181 studies a separate bucket-guard sampler. None recovers these node115 pair fields and collection gates. The audit records missing patches and API limits rather than treating absence of text as proof of no overlap.

`validation.json` and compressed logs preserve required checks and the reused, identical-commit baseline. No component gate changes. Raw/normalized compiled matches are **not measured**. The next question is the exact contract of the group-entry helpers `0x4dc46c0` / `0x4da50b0`, including key equality, default construction and alternate-representation iteration.
