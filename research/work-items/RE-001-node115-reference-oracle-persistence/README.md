# RE-001: node115 reference-oracle persistence and price-update gate

- Component: `risk`; bounded static research, no reconstructed Rust implementation.
- Target: Linux x86-64 node **#115**, 105896032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Repository base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Coordinates: ELF virtual addresses, exclusive range ends; file offsets are in
  `records.json`. No relocation normalization or byte masks.
- Status: native observations plus conditional local deductions. Source names,
  price/timestamp roles and persistence labels are inferences; opaque helper
  contracts and whole-oracle behavior remain unresolved.

## Bounded result

The decision at `0x366f900` has a stateful path that updates two timestamp-shaped
records and projects a helper-returned signed pair into a nonnegative double.
Its threshold comparison gates a **code-8 helper request**, not a change to the
normally returned flag: the stateful path returns the configuration byte's low
bit both before and after that threshold. In the selected caller, a nonzero
return suppresses the proposed price-field store. Thus this evidence does not
support a reconstruction that clears the hold merely because the threshold
has elapsed. Helper divergence or exceptions are outside the normal-return claim.

A separate ratio gate uses unsigned `max(p,q) / min(p,q) - 1` with binary64
rounding. Only a strictly larger clamped tolerance requests the reset/remove-
shaped helper and returns false; equality retains the stateful route. The entry
helper's insertion-shaped paths submit a `10.0` seed and two zero dword markers.
Neither the actual time unit nor universal propagation of that seed is proven.

See [PROOF.md](PROOF.md) for instruction-by-instruction argument, boundary
semantics, raw layouts, helper premises and prior-work attribution.

| Exported role | Complete FDE range | Bytes | Instructions | Claim scope |
| --- | --- | ---: | ---: | --- |
| Decision | `0x366f900..0x366fbe4` | 740 | 183 | local branch, write and return relations |
| Entry context | `0x3f15c10..0x3f15db0` | 416 | 107 | new-entry seed and marker writes |
| Caller context | `0x53811a0..0x5381546` | 934 | 190 | two requests and conditional price-field stores |

The total **2090 bytes / 480 instructions** is the export denominator, not a
semantic-closure or reconstruction percentage. Full semantics of the two
context functions are not claimed. All 27 explicit calls in these bodies are
retained with direct/relocation targets. Fourteen selected RELATIVE bindings,
seven literal/Location records, 23 instruction-span obligations and three FDEs
are authenticated. An encoded-form incoming census qualifies 11 sites against
full owning-FDE decoding; it is not an arbitrary-indirect-call graph.

## Reproduce

Materialize the repository's pinned submodules and LFS inputs as documented in
CONTRIBUTING.md. Use Python 3 with Capstone, GNU binutils and LLVM on PATH.
From the repository root:

```sh
python3 research/work-items/RE-001-node115-reference-oracle-persistence/export_disassembly.py
python3 research/work-items/RE-001-node115-reference-oracle-persistence/verify.py --controls
python3 research/work-items/RE-001-node115-reference-oracle-persistence/relations.py
python3 -m unittest discover -s tests -p test_node115_reference_oracle_persistence.py -v
make doctor verify test catalogue-check reproduce
shasum -a 256 -c research/work-items/RE-001-node115-reference-oracle-persistence/MANIFEST.sha256
```

The exporter hashes the input before creating a nonexecutable temporary copy,
then uses GNU `objdump -d -Mintel --insn-width=15`, LLVM
`llvm-objdump -d --x86-asm-syntax=intel`, and GNU `readelf --debug-dump=frames`.
Both decoders cover every byte of each selected FDE and agree on instruction
starts. `verify.py` regenerates records and deep corruption results;
`relations.py` checks static algebra and branch truth tables. No captured code
is executed or emulated. The Python relations are explicit deductions, not a
substitute implementation, ISA runner or differential comparison with the node.

`validation.json` and its compressed logs preserve actual commands, versions,
results and setup/test failures. `MANIFEST.sha256` covers this packet and the
focused test. The gzip audit/log files are ordinary Git evidence, not new LFS
objects. Native export text is retained without semantic normalization.

## Validation scope and remaining work

The unchanged base passed the full required command (76 modules / 382 reported
cases). The contribution ran all 77 modules / 386 cases with the same three
skips. One manifest test caught an audit archive refreshed after its checksum;
regenerating the manifest fixed it, and all 12 tests in that affected module
passed. The other 76 modules, including the four new tests, had passed unchanged.
Post-repair doctor, verification, catalogue and reproduction checks passed;
no second full-suite pass is claimed. Raw results are retained in `validation.json`.

The controls reject 47 altered instruction/data/relocation/FDE inputs while
bypassing image, body-digest and export-byte guards, plus eight actual operand
counterfacts that change the extracted relation before rejection. Independent
integer rounding checks cover 554 u64 boundary values; there are 14 hand-selected
ratio boundaries, 56 pair normalization boundaries and 1024 flag/comparison
cases. Finite controls accompany the written argument; they do not prove all
runtime behaviors. Default binary64 rounding, masked FP exceptions, quiet NaNs,
valid memory/container inputs and normal helper returns are explicit premises.

The all-state PR and reachable-main-history audit is recorded in `overlap.json`.
Earlier oracle stage-order and configuration research, the shared signed-pair
projection, and source-path inventories are credited there. This packet resolves
the distinct persistence/return/caller-use question. No progress gate or component
completion score is changed. Pinned upstream inputs and reference source remain
unchanged. New prose and code are independently authored under the repository's
MIT license; generic export/checker structure is adapted from the MIT packet in
PR #2111. No unlicensed inferred implementation was copied.

Next question: recover the entry/reset helpers and the code-8 callee contract,
then establish the actual timebase and other writers of the entry's threshold.
