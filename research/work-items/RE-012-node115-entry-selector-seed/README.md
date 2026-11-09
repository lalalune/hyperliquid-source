# RE-012: entry callback selector trace

## Scope

This packet records one static path in the pinned Node #115 artifact: an entry callback initializes its output selector byte to zero, passes an output buffer through a wrapper, and the executor reads the corresponding byte and dispatches through table entry zero. The selected case calls through a relocated slot to `0x564d700`, the CLI builder mapped by the adjacent RE-012 parser-call packet.

It does not identify the callback with `run-validator` or `run-non-validator`; establish runtime reachability; show which command reaches the builder; map the selected arm to checkpoint selection or storage; or resolve issue #3927. A separate direct executor caller exists, so this result is limited to the callback path anchored here.

## Evidence

`evidence.json` pins `artifacts/node/115/hl-node` by SHA-256 and file size. Five byte anchors are checked against their `.text` virtual addresses and FDE extents. The verifier also checks the relative dispatch-table entry, the dynamic relocation identifying the wrapper's copy import as `memcpy`, the case-0 call slot resolving to `0x564d700`, and a negative control that changes the callback's initialized selector byte.

The observed stack offsets connect the callback's `[rsp+0x222]` byte to the wrapper's copied buffer and then to the executor's `[rdi+0x21a]` load. Entry zero resolves to `0x2ae420b` for this path and that arm calls the CLI builder through slot `0x64e73c0`.

## Reproduction

From the repository root, with Python 3 and the repository's packet tools available:

```sh
python3 research/work-items/RE-012-node115-entry-selector-seed/verify.py
python3 tools/verify_packets.py
git diff --check
```

The focused verifier reports the artifact digest, instruction anchors, copy relocation, dispatch entry, and negative control as verified. The repository-wide packet verifier is included to check packet integration. No captured binary is executed.

## Provenance and limits

- Target: `artifacts/node/115/hl-node`
- Target SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Base revision: `0781ce04826eeefd89fe336cb8ea073be0c1de30`
- Analysis tools: Python packet parsers in `tools/`; GNU binutils 2.47.20260726 was used for the preceding disassembly review.
- Evidence is static and artifact-specific. It does not establish behavior for another artifact revision.
