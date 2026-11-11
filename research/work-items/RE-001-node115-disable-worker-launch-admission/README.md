# RE-001: node #115 disable-worker launch admission and optional home-address precedence

- Component: `node-runtime`; bounded preparatory static research for RE-001.
- Base commit: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses, exclusive end addresses. Source names are captured Location/string observations, not recovered source.
- Status: measured caller instructions and data; inferred descriptive labels; helper semantics and original public types remain unresolved.
- No captured binary execution, emulation, live-node queries, signing or chain actions. No new Rust implementation or target-equivalence claim; all full-component gates stay false.

## Result

Launcher `0x5a6cfb0..0x5a6d1f1` decides whether to construct the already studied `node_disabler` worker. Request byte exactly 1 skips the `is_main_signer` operation. Other request bytes copy 20 bytes from request+1 and call wrapper `0x4f16fb0` with the exact 14-byte operation name. A **nonzero AL** from that wrapper decrements/releases the retained owner reference, consumes the request through `0x5a4bab0`, and returns without examining the optional home address.

Only the remaining routes inspect bit 0 of the packed RDX argument. A clear bit takes the fatal diagnostic boundary with the 28-byte text `Could not get home public ip` and its node.rs:962 Location. A nonzero low byte alone is insufficient: byte 2 fails while byte 3 passes. A set bit shifts the packed word right 8, then retains its low 32 bits as the address-like field. Bits above bit 39 do not affect that field. Byte order and public address type are not inferred.

The launch path copies 0x78 request bytes, stores the owner, stores the 32-bit address and an initial state byte 0, allocates 0x120 bytes and copies the prepared 0x120-byte future-shaped storage. The final call `0x15d6730` receives the 13-byte `node_disabler` name and raw numeric argument 1. This proves the launch request and its operand routing, not successful worker execution. The descriptor at `0x64b8ac8` binds size 0x120, alignment 8 and the RELATIVE poll slot at `0x64b8ae0` to `0x5a6d200`, the periodic body from #2536. Its implementation is prior context. Some temporary bytes are inactive or not established here and must not be modeled as zero.

Prior #2536 reconstructs the launched worker's periodic disable predicate and its 10.0 wait input. This contribution closes the **preceding launch decision**, notably that an affirmative main-signer query makes a missing home address irrelevant, whereas exact request tag 1 bypasses that query and still requires the address. The query implementation, original request enum, allocator/spawn/destructor semantics and runtime effects remain opaque.

The native denominator is **1 complete FDE / 577 bytes / 125 instructions**. The four packet tests pass with 32/32 deeper corruption controls rejected, 24,576 caller-projection cases and three distinguishing counterfactuals. These counts measure static evidence and check coverage, not reconstructed implementation bytes.

## Reproduce

Run from the repository root with the pinned artifact/submodules and research LFS inputs materialized. Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM are the validation environment; exact observed versions and outcomes are in `validation.json`.

```sh
python3 research/work-items/RE-001-node115-disable-worker-launch-admission/export_disassembly.py
python3 research/work-items/RE-001-node115-disable-worker-launch-admission/verify.py --controls
python3 research/work-items/RE-001-node115-disable-worker-launch-admission/relations.py
python3 -m unittest discover -s tests -p 'test_node115_disable_worker_launch_admission.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-disable-worker-launch-admission/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

`--write` on the verifier or relation checker regenerates the committed JSON. The export script uses GNU objdump, LLVM objdump and GNU readelf without loading or executing the target. The verifier authenticates the complete target first, binds full FDEs and their digests, compares every instruction byte/boundary in both decoders, and validates selected instruction obligations, literals, source Locations, RELATIVE call/data bindings and applicable dynamic imports. The incoming census qualifies E8 and RIP-relative FF15/FF25 forms with complete FDE decoding; it is not a census of arbitrary register/vtable dispatch.

`controls.json` deliberately bypasses whole-image, body-hash and saved-export guards to test deeper instruction/data/relocation/FDE checks. Separate tests enforce those outer guards. `relations.json` compares caller-level projections derived from native operands with independent arithmetic or ordered-event statements, including three changed-operand counterfactuals. These projections do not execute or emulate captured instructions and do not establish runtime equivalence.

## Scope and provenance

Large audit snapshots, common-file hashes and test logs are stored as deterministic `.bz2` files to keep the review diff focused. `validation.json` binds both compressed and uncompressed hashes. Read a compressed text artifact with `python3 -c 'import bz2,sys; sys.stdout.buffer.write(bz2.open(sys.argv[1], "rb").read())' <artifact.bz2>`. Native disassembly, semantic records and check code remain plain text.

`scope-check.json` records the all-state PR audit, exact address terms, related prior work and audit limits. Current main and reachable research/tool/test/doc/source history were searched as well as PR titles, bodies, file names and available patches. Related PRs: [2536](https://github.com/lalalune/hyperliquid-source/pull/2536), [1138](https://github.com/lalalune/hyperliquid-source/pull/1138). The result is a bounded no-overlap finding at the recorded snapshot, not a reservation against future work.

New analysis and verification code are independently authored under the repository MIT license. Generic parsing/export helpers adapt the repository's MIT research packets; no unlicensed inferred reference source was copied. Imported artifacts and reference submodules remain pinned and unchanged. `records.json` supplies the measured native denominator; there is no source-to-binary comparison, normalization mask, implementation-byte registration or completion percentage.

## Validation and remaining question

See `validation.json` and the retained logs for actual pass/fail results, environment repairs and baseline limitations. No hosted CI or container result is claimed. The next question is to recover the `is_main_signer` query implementation behind the wrapper with independent source and digest-bound evidence.
