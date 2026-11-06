# RE-001: node #115 spot iterator inner-first rollover and fallback ordering

- Component: `assets`; bounded preparatory static research for RE-001.
- Base commit: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses, exclusive end addresses. Source names are captured Location/string observations, not recovered source.
- Status: measured caller instructions and data; inferred descriptive labels; helper semantics and original public types remain unresolved.
- No captured binary execution, emulation, live-node queries, signing or chain actions. No new Rust implementation or target-equivalence claim; all full-component gates stay false.

## Result

The complete iterator `0x22b3d40..0x22b3eff` first calls `0x2315e80` on its current state. Any nonzero first result byte is forwarded as a 24-byte result immediately. Only raw tag 0 enters outer-row rollover. No public Iterator/Option variant name is asserted.

Outer-row exhaustion has two independent checks: state+0x2b0 must be nonzero, and cursor+0x2b8 must differ from end+0x2c8. On exhaustion the same poll helper receives state+0x158. Otherwise the caller reads a 16-byte descriptor, **advances the cursor by 16 before checking its index**, and requires its first qword strictly below metadata+0x10. It selects the leading 16 bytes of a 32-byte metadata row. The descriptor's second qword, a copied 20-byte context and a temporary output are passed to `0x23e0c90`.

After that opaque converter returns, the caller combines the retained metadata, another captured qword and the index into temporary state. It copies a 0x150-byte state before calling the current-state destructor `0x2313440`; only then does it publish current-state qword 2 and copy the new 0x150 bytes to state+8. It polls the replacement with `0x2315e80`. Another raw 0 loops back to the next outer descriptor; a nonzero result is forwarded. Thus the fallback is polled only after outer exhaustion, never between successful inner results. A bounds failure has already consumed the outer descriptor's cursor step.

The landing path at 0x22b3ed7 also installs the prepared state before resuming an unwind from the old-state drop. This is visible cleanup context, not a claim of panic safety, valid original Rust ABI, or full initialized payload. The inner poll, converter, destructor and source collection remain opaque. Native obligations and ordered-event projections distinguish existing-inner success, rollover, bounds rejection and fallback. There is no captured execution or instruction interpreter.

Prior #2629 addresses a different per-DEX collector with 0x510/0x110 strides and completed-prefix publication. #2538 returns labels for registry rows. Neither establishes this lazy inner-first rollover and fallback state machine.

The native denominator is **1 complete FDE / 447 bytes / 96 instructions**. The four packet tests pass with 14/14 deeper corruption controls rejected, 480 caller-projection cases and three distinguishing counterfactuals. These counts measure static evidence and check coverage, not reconstructed implementation bytes.

## Reproduce

Run from the repository root with the pinned artifact/submodules and research LFS inputs materialized. Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM are the validation environment; exact observed versions and outcomes are in `validation.json`.

```sh
python3 research/work-items/RE-001-node115-spot-iterator-inner-rollover/export_disassembly.py
python3 research/work-items/RE-001-node115-spot-iterator-inner-rollover/verify.py --controls
python3 research/work-items/RE-001-node115-spot-iterator-inner-rollover/relations.py
python3 -m unittest discover -s tests -p 'test_node115_spot_iterator_inner_rollover.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-spot-iterator-inner-rollover/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

`--write` on the verifier or relation checker regenerates the committed JSON. The export script uses GNU objdump, LLVM objdump and GNU readelf without loading or executing the target. The verifier authenticates the complete target first, binds full FDEs and their digests, compares every instruction byte/boundary in both decoders, and validates selected instruction obligations, literals, source Locations, RELATIVE call/data bindings and applicable dynamic imports. The incoming census qualifies E8 and RIP-relative FF15/FF25 forms with complete FDE decoding; it is not a census of arbitrary register/vtable dispatch.

`controls.json` deliberately bypasses whole-image, body-hash and saved-export guards to test deeper instruction/data/relocation/FDE checks. Separate tests enforce those outer guards. `relations.json` compares caller-level projections derived from native operands with independent arithmetic or ordered-event statements, including three changed-operand counterfactuals. These projections do not execute or emulate captured instructions and do not establish runtime equivalence.

## Scope and provenance

Large audit snapshots, common-file hashes and test logs are stored as deterministic `.bz2` files to keep the review diff focused. `validation.json` binds both compressed and uncompressed hashes. Read a compressed text artifact with `python3 -c 'import bz2,sys; sys.stdout.buffer.write(bz2.open(sys.argv[1], "rb").read())' <artifact.bz2>`. Native disassembly, semantic records and check code remain plain text.

`scope-check.json` records the all-state PR audit, exact address terms, related prior work and audit limits. Current main and reachable research/tool/test/doc/source history were searched as well as PR titles, bodies, file names and available patches. Related PRs: [2629](https://github.com/lalalune/hyperliquid-source/pull/2629), [2538](https://github.com/lalalune/hyperliquid-source/pull/2538). The result is a bounded no-overlap finding at the recorded snapshot, not a reservation against future work.

New analysis and verification code are independently authored under the repository MIT license. Generic parsing/export helpers adapt the repository's MIT research packets; no unlicensed inferred reference source was copied. Imported artifacts and reference submodules remain pinned and unchanged. `records.json` supplies the measured native denominator; there is no source-to-binary comparison, normalization mask, implementation-byte registration or completion percentage.

## Validation and remaining question

See `validation.json` and the retained logs for actual pass/fail results, environment repairs and baseline limitations. No hosted CI or container result is claimed. The next question is to recover the row converter at `0x23e0c90`, its variant layout and valid input contract with independent source and digest-bound evidence.
