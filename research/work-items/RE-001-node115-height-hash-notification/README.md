# RE-001: node #115 current-height last-record notification admission

- Component: `node-runtime`; bounded preparatory static research for RE-001.
- Base commit: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses, exclusive end addresses. Source names are captured Location/string observations, not recovered source.
- Status: measured caller instructions and data; inferred descriptive labels; helper semantics and original public types remain unresolved.
- No captured binary execution, emulation, live-node queries, signing or chain actions. No new Rust implementation or target-equivalence claim; all full-component gates stay false.

## Result

Notifier `0x5a6c8f0..0x5a6cbbb` reads a height-like value at captured owner+0x28. Its source Location and literal explicitly refer to `freeze_height >= self.locus.context.height()`. With freeze DWORD tag 1 at owner+0x10e8, a target below the current value takes the fatal boundary **before any modulo check**; equality returns immediately. Other cases proceed to the unsigned modulo test against owner+0x39c8. Only remainder0 continues. The DIV has32-bit and 64-bit paths depending on operand widths; nonzero cadence is a normal-path premise, and a zero divisor's trap is not silently modeled as skip. Outer low DWORD tag 2 suppresses notification after cadence.

The caller then selects the last record in the collection at outer+0x400. A signed-minimum first qword selects a tree representation: root+0x408 and depth+0x410, descending the rightmost child at each level using node count+0x1c2 and child array+0x1c8. A nonempty leaf supplies its final qword key and 32-byte value. Other first words select a circular representation with capacity at+0x400, storage+0x408, start+0x410 and length+0x418. For valid nonempty descriptors it computes `start+length-1`, subtracts capacity once when needed, and selects a 40-byte row. Valid bounds/no-overflow descriptors are explicit premises.

Both routes require the **last key to equal the current height exactly**. Empty collections, earlier last keys and future last keys do not hand off. On equality a stack record contains the current8-byte height followed by the 32-byte value. The channel helper `0x581a4f0` receives a pointer to that 40-byte stack record only after a visible channel-state admission CAS; an already closed low bit unwinds the auxiliary increment and skips the handoff. Wakeup/queue internals remain opaque, so this is not proof of delivery or snapshot finality.

Prior #2267 reconstructs exchange preparation preludes where cadence precedes a past-target test; that ordering must not be copied into this different notifier. #2181 traces snapshot/root inputs, and #2085 filesystem checkpoint preparation. Their functionality is context, not repeated reconstruction. This packet closes the separately unmeasured current-height last-record selection and notification boundary.

The native denominator is **1 complete FDE / 715 bytes / 152 instructions**. The four packet tests pass with 13/13 deeper corruption controls rejected, 19,120 caller-projection cases and three distinguishing counterfactuals. These counts measure static evidence and check coverage, not reconstructed implementation bytes.

## Reproduce

Run from the repository root with the pinned artifact/submodules and research LFS inputs materialized. Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM are the validation environment; exact observed versions and outcomes are in `validation.json`.

```sh
python3 research/work-items/RE-001-node115-height-hash-notification/export_disassembly.py
python3 research/work-items/RE-001-node115-height-hash-notification/verify.py --controls
python3 research/work-items/RE-001-node115-height-hash-notification/relations.py
python3 -m unittest discover -s tests -p 'test_node115_height_hash_notification.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-height-hash-notification/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

`--write` on the verifier or relation checker regenerates the committed JSON. The export script uses GNU objdump, LLVM objdump and GNU readelf without loading or executing the target. The verifier authenticates the complete target first, binds full FDEs and their digests, compares every instruction byte/boundary in both decoders, and validates selected instruction obligations, literals, source Locations, RELATIVE call/data bindings and applicable dynamic imports. The incoming census qualifies E8 and RIP-relative FF15/FF25 forms with complete FDE decoding; it is not a census of arbitrary register/vtable dispatch.

`controls.json` deliberately bypasses whole-image, body-hash and saved-export guards to test deeper instruction/data/relocation/FDE checks. Separate tests enforce those outer guards. `relations.json` compares caller-level projections derived from native operands with independent arithmetic or ordered-event statements, including three changed-operand counterfactuals. These projections do not execute or emulate captured instructions and do not establish runtime equivalence.

## Scope and provenance

Large audit snapshots, common-file hashes and test logs are stored as deterministic `.bz2` files to keep the review diff focused. `validation.json` binds both compressed and uncompressed hashes. Read a compressed text artifact with `python3 -c 'import bz2,sys; sys.stdout.buffer.write(bz2.open(sys.argv[1], "rb").read())' <artifact.bz2>`. Native disassembly, semantic records and check code remain plain text.

`scope-check.json` records the all-state PR audit, exact address terms, related prior work and audit limits. Current main and reachable research/tool/test/doc/source history were searched as well as PR titles, bodies, file names and available patches. Related PRs: [2267](https://github.com/lalalune/hyperliquid-source/pull/2267), [2181](https://github.com/lalalune/hyperliquid-source/pull/2181), [2085](https://github.com/lalalune/hyperliquid-source/pull/2085). The result is a bounded no-overlap finding at the recorded snapshot, not a reservation against future work.

New analysis and verification code are independently authored under the repository MIT license. Generic parsing/export helpers adapt the repository's MIT research packets; no unlicensed inferred reference source was copied. Imported artifacts and reference submodules remain pinned and unchanged. `records.json` supplies the measured native denominator; there is no source-to-binary comparison, normalization mask, implementation-byte registration or completion percentage.

## Validation and remaining question

See `validation.json` and the retained logs for actual pass/fail results, environment repairs and baseline limitations. No hosted CI or container result is claimed. The next question is to trace the producer of the height-keyed collection and establish the meaning of its 32-byte values with independent source and digest-bound evidence.
