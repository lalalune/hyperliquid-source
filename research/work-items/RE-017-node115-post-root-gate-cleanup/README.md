# RE-017 · Post-root gate and end-selector cleanup contract

The existing post-root packet records the gate's cleanup edge at `0x5a6dd22`. The same cleanup at `0x5a4f110` is reached by the block engine at `0x5a07c57` and by the end-selector at `0x5a08f3c`. The selected end-selector path passes stack +0xa8 and then resumes unwinding. This packet verifies the callee's previously unrecorded body and the two additional edges.

The callee has two independent zero guards. The first tests +0, passing +8 as the first argument and +0 as the second when nonzero. The second tests +0x18 and tail-transfers +0x20 and +0x18 when nonzero. Both pass a zero third argument to slot `0x64df4a0`. Unlike the contextual block-caller variant at `0x4f35280`, this gate-side function has no minimum-signed-word bypass. Interpreting the two descriptors as having a common sentinel guard would give the wrong control-flow model. This is a static control-flow distinction. The valid descriptor domain, actual slot effects and root validation behavior remain open.

From the repository root run `python3 research/work-items/RE-017-node115-post-root-gate-cleanup/verify.py`. The verifier checks the pinned capture, function extent and all three direct edges. It checks the end-selector unwind continuation and rejects a mutated call displacement.
