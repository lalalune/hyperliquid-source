# RE-001: node #115 finalization callback control-flow envelope

- Component: binary/function map, bounded startup lifecycle research.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes.
- Claim status: static observations plus explicitly bounded interpretation. No reconstruction gate requested.

## Question and result

The sole `.fini_array` slot at VA `0x63f36c0` / file `0x63f16c0` is zero in the file and has a symbol-zero `R_X86_64_RELATIVE` relocation with addend `0x14193a0`. Prior integrated table and FDE-gap packets identify the entry/island, not the callback's internal control flow. This packet resolves the guard, reachable native envelope and two outgoing direct calls. It does not claim new discovery of the table slot.

Entry `0x14193a0` begins with `endbr64`. A byte comparison at `0x14193a4` reads guard VA `0x64ffe40`: the nonzero branch at `0x14193ab` reaches the early return at `0x14193d8`. Otherwise the callback saves rbp, tests the pointer slot at `0x64df478`, and conditionally calls `0x63f0a40` at `0x14193c2`. Both pointer-test arms reach direct call `0x14193c7 -> 0x1419330`; the callback then writes byte 1 to the same guard, restores rbp and returns at `0x14193d4`. The reachable instruction envelope is `[0x14193a0,0x14193d9)`, including internal padding; this is NOT a symbol-table or unwind-derived exclusive function extent. No return-flow proof about the callees is supplied.

A complete GNU readelf 2.40 frame dump parsed 135313 FDE ranges, none containing the callback. Adjacent FDEs are `[0x1419300,0x1419326)` and `[0x14193f0,0x1419618)`. FDE absence by itself is not the new result. Native objdump 2.40 output retained in `selected.objdump.txt` covers 256 bytes beginning at `0x1419330`; it includes neighboring code and a split final instruction outside the selected callback. Only complete aligned callback instructions support this envelope.

## Reproduce and controls

Run from repository root:

```sh
python3 research/work-items/RE-001-node115-fini-callback-boundary/discover.py
python3 research/work-items/RE-001-node115-fini-callback-boundary/byte_proof.py
```

`discover.py` authenticates the target, parses ELF sections/relocations, and invokes the native static commands recorded in `discovery.json`. `byte_proof.py` independently reads section VA/file mappings, checks the callback instruction prefixes, decodes signed conditional/direct displacements and RIP-relative guard references, and resolves selected dynamic relocations. Actual byte results and PLT/symbol evidence are in `byte-proof.json`; native symbol labels alone are not treated as proof. Four artifact-byte corruption controls (entry, branch target, direct-call displacement, guard-store immediate) were rejected; identical input derives identically. These are executed controls, not a scoped unittest suite or independent project validation.

## Scope, provenance and limits

All analysis is static; the captured target was not loaded or executed. New scripts and prose are independently authored; imported bytes/excerpts retain upstream rights and are not offered as MIT source reconstruction. Setup manifests, hooks and AGENTS were inspected at this same pinned baseline; the frida install hook was not executed. No package installation or repository helper execution was used for these observations. Prior setup reads were output-truncated; compact AGENTS/hook summaries were subsequently read without truncation.

Exact public PRs #2494 and #40 supplied prior table/island scope, and #2755's body concerns a different main-entry thunk. A current open-PR body/title literal query for `14193a0` returned zero; that is bounded discovery evidence, not a complete novelty proof. The controller retains selection/publication overlap evidence.

At the original milestone no formal tests or required make checks were claimed. The scoped follow-up below does not establish independent validation, target equivalence, runtime destructor ordering, once-only execution guarantee, dependency closure or component completion is claimed. Static guard structure does not establish synchronization or runtime reachability. The helper at `0x1419330` and all effects of imported finalizers remain outside the semantic claim.

## Scoped replay acceptance

The new scoped file `tests/test_node115_fini_callback_boundary.py` exercises the real authenticated artifact, relocation-backed dynamic symbol naming, branch/call and RIP-relative decoding, complete native callback alignment and a fresh full GNU readelf FDE census. It also mutates instruction fields, relocation types/symbols/addends, the PLT jump and recorded fields. Tests deliberately bypass target hashing for field-level controls; normal replay authenticates first. The first test attempt exposed two incorrectly chosen PLT *file* offsets in the test, not a target mismatch. Those controls now derive their file coordinates from ELF section mapping and the same nine-test command passes; see `scoped-results.json` for actual output. No existing executable project code is changed.

Independent project validation is still required before publication. Full/reduced REA, runtime execution, helper semantics, synchronization, source reconstruction and component gates remain outside this packet.
