# RE-001: node94 thread stack policy and worker handoff

This bounded static packet recovers the production constructor's explicit,
cached and environment-derived stack-size selection, its join-result layout,
and its fixed worker callback. The selected native bodies are
`0x1448270..0x1448820` (1,456 bytes) and `0x1451a90..0x1451bed` (349 bytes).
The comparison denominator is two complete FDEs / 1,805 bytes, not a Rust build
or component-completion claim. Detailed proof, overlap and validation records
accompany this packet before publication.

Target: node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `966865f1637a29ce75b019e1bf11d5529cc6f519`.
Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
All coordinates are ELF virtual addresses with exclusive ends. New evidence
and verifier code are independently authored under MIT; original binary
excerpts retain their own rights. The shared native pthread adapter is already
covered by #1640 and is not recovered again here. No target execution or
emulation, live network, signing, or progress-gate change is requested.
