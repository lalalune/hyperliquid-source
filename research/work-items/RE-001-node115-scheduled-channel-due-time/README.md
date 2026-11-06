# RE-001: node #115 scheduled channel due-time normalization and wait ordering

- Component: `transport`; bounded preparatory static research for RE-001.
- Base commit: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses, exclusive end addresses. Source names are captured Location/string observations, not recovered source.
- Status: measured caller instructions and data; inferred descriptive labels; helper semantics and original public types remain unresolved.
- No captured binary execution, emulation, live-node queries, signing or chain actions. No new Rust implementation or target-equivalence claim; all full-component gates stay false.

## Result

The complete worker `0x5a71040..0x5a7172a` contains a timed channel loop. This packet isolates the caller's due-time decision and retained-item lifecycle. Generic queue admission, waker registration, cooperative scheduling and drop mechanics remain context already studied elsewhere.

After an ordinary receive result with nonzero payload classification, the worker saves the received 12-byte time triple and retains a qword at state+0x68 before sampling the current time through the call at 0x5a7142c. It compares the first DWORD **signed**, then the second and third DWORDs **unsigned**. An earlier due triple supplies binary64 +0.0 without calling the difference helper. Equality does call the helper: the final branch is unsigned greater-or-equal.

The difference call at 0x5a7146e returns RAX/EDX. When RAX is negative and EDX is positive, the caller adds1 to RAX and subtracts1,000,000,000 from EDX, then converts both signed integers to binary64 and adds `seconds + nanos/1e9`. MAXSD with a zero second operand replaces negative/unordered results with +0.0. The subsequent infinity comparison also chooses +0.0 on equality/unordered. For the finite i64/i32 outputs used in the relations, the conversion cannot produce infinity; the guard is retained without inventing reachable exceptional values or calendar units.

The resulting value is stored at state+0x70 and nested sleep-state+0x100 is reset to0. The worker polls `0x5a2f550` before another receive cycle. A nonzero AL returns AL1 with outer state+0x61=4, retaining the pending item. A ready sleep proceeds to the next send/receive cycle. The existing generic receive-pending path instead stores outer state 3. No actual delay, scheduler progress or delivery guarantee follows from these numeric/caller observations.

Prior #2535 recovers receiver completion/budget rules, and #2534 arbitration among three channels. They do not establish this due-time arithmetic or the wait before the next cycle. Those generic receive mechanisms are exported only as context here; helper internals, public time types, payload meaning, aliases, cancellation and concurrency remain open.

The signed-relative dispatch table at `0x93970c` maps outer state 0 to the initial receive setup, state 3 to receiver resumption, and state 4 directly to the sleep poll at `0x5a7114e`. States1/2 lead to terminal-poll diagnostics. The two nested four-entry tables at `0x939720` and `0x939730` are byte-bound context. Valid outer/nested state values are a premise; arbitrary out-of-range tags are not modeled.

The native denominator is **1 complete FDE / 1770 bytes / 399 instructions**. The four packet tests pass with 40/40 deeper corruption controls rejected, 4,116 caller-projection cases and three distinguishing counterfactuals. These counts measure static evidence and check coverage, not reconstructed implementation bytes.

## Reproduce

Run from the repository root with the pinned artifact/submodules and research LFS inputs materialized. Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM are the validation environment; exact observed versions and outcomes are in `validation.json`.

```sh
python3 research/work-items/RE-001-node115-scheduled-channel-due-time/export_disassembly.py
python3 research/work-items/RE-001-node115-scheduled-channel-due-time/verify.py --controls
python3 research/work-items/RE-001-node115-scheduled-channel-due-time/relations.py
python3 -m unittest discover -s tests -p 'test_node115_scheduled_channel_due_time.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-scheduled-channel-due-time/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

`--write` on the verifier or relation checker regenerates the committed JSON. The export script uses GNU objdump, LLVM objdump and GNU readelf without loading or executing the target. The verifier authenticates the complete target first, binds full FDEs and their digests, compares every instruction byte/boundary in both decoders, and validates selected instruction obligations, literals, source Locations, RELATIVE call/data bindings and applicable dynamic imports. The incoming census qualifies E8 and RIP-relative FF15/FF25 forms with complete FDE decoding; it is not a census of arbitrary register/vtable dispatch.

`controls.json` deliberately bypasses whole-image, body-hash and saved-export guards to test deeper instruction/data/relocation/FDE checks. Separate tests enforce those outer guards. `relations.json` compares caller-level projections derived from native operands with independent arithmetic or ordered-event statements, including three changed-operand counterfactuals. These projections do not execute or emulate captured instructions and do not establish runtime equivalence.

## Scope and provenance

Large audit snapshots, common-file hashes and test logs are stored as deterministic `.bz2` files to keep the review diff focused. `validation.json` binds both compressed and uncompressed hashes. Read a compressed text artifact with `python3 -c 'import bz2,sys; sys.stdout.buffer.write(bz2.open(sys.argv[1], "rb").read())' <artifact.bz2>`. Native disassembly, semantic records and check code remain plain text.

`scope-check.json` records the all-state PR audit, exact address terms, related prior work and audit limits. Current main and reachable research/tool/test/doc/source history were searched as well as PR titles, bodies, file names and available patches. Related PRs: [2534](https://github.com/lalalune/hyperliquid-source/pull/2534), [2535](https://github.com/lalalune/hyperliquid-source/pull/2535), [2297](https://github.com/lalalune/hyperliquid-source/pull/2297). The result is a bounded no-overlap finding at the recorded snapshot, not a reservation against future work.

New analysis and verification code are independently authored under the repository MIT license. Generic parsing/export helpers adapt the repository's MIT research packets; no unlicensed inferred reference source was copied. Imported artifacts and reference submodules remain pinned and unchanged. `records.json` supplies the measured native denominator; there is no source-to-binary comparison, normalization mask, implementation-byte registration or completion percentage.

## Validation and remaining question

See `validation.json` and the retained logs for actual pass/fail results, environment repairs and baseline limitations. No hosted CI or container result is claimed. The next question is to recover the two time-helper contracts and establish the typed domain of the three comparison words with independent source and digest-bound evidence.
