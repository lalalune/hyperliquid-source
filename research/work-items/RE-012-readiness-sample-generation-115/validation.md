# Validation scope

Static Windows host, Python 3.12.14, Capstone 5.0.6, pyelftools 0.32. Baseline
`7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

- Exact full target digest, complete FDE/CIE and instruction walk; records and
  listing regenerate exactly. The final command result is stated in the PR.
- Thirteen operative mutations are checked below the whole-file digest guard.
- 16,384 finite conditional branch cases plus the mode-2 witness. The models
  exclude callback writes/interleavings and never execute target instructions.
- An earlier packet sweep in this checkout passed 1,754 manifests / 20,512
  entries after LFS materialization (65 historical unresolved rows); it
  included the preceding, separately submitted readiness-admission packet.
  That aggregate is not claimed as an exact-head sweep of this branch.
- Baseline artifact size/SHA-256 checks pass, but its signature stage cannot
  discover GPG through this host's default executable search. Doctor reports
  native binutils, Ghidra and Rust toolchains unavailable.

The complete repository suite, inventory reproduction and hosted CI are not
claimed to pass. Packet manifest, generated inventory and remote byte checks
are recorded for this branch in the PR description. No existing evidence,
component gate, dependency pin or byte-window registry is modified.
