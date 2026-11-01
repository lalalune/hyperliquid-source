# Pre-code scope and dependency plan

This file and the mathematical corpus precede new Rust. No new implementation is claimed at this phase. Root must admit the complete proof/corpus/source plan before writing source; that gate is distinct from later validation.

Proposed integration is the existing `src/node94-consensus-admission` Cargo package on main56c0ec672bd8fdcfaa80f2db700a61e6240b3663. Keep its baseline SignedBlock/Qc/QcVote/TimeoutVote/Tc/SignatureBytes and AdmissionAuthenticator unchanged. SignedBlock omits native block time, so the new operation takes an explicit three-word value:
`PackedBlockTime { packed_date: i32, seconds: u32, nanoseconds: u32 }`.
This intentionally admits raw words and does not validate chrono's calendar/flag invariants.

Proposed new bounded public operations in `block_preimage.rs` are encoded length, preimage bytes and digest for `(&SignedBlock, PackedBlockTime)`. Result errors are chosen checked-length/allocation refusals, not target ABI statuses. Capacity/stride checks are separate from scalar encoding. The digest API remains conditional on the existing Keccak structural identity. It performs no signing, recovery, key access, networking or admission mutation.

Only the existing baseline MIT scalar package `hl-bincode-varint` and `node94-action-signable` Keccak are proposed path dependencies; hashes are in dependencies.json. The actual package manifests/lock/build graph, all build scripts/ancestor Cargo configuration and pinned toolchain must be audited again before compilation. Cargo-generated lock only; no artificial workspace or reference source.

Root selected narrowly private block wire helpers on baseline. They implement only selector0's nested signature/QC/timeout projections; they do not add a duplicate public timeout API or depend on pending1391/1467. Later integration of those PRs can consolidate internal code under a reviewed source change, but that future consolidation is not part of this proof or a hidden dependency.

Proposed owned source paths:
- src/node94-consensus-admission/src/block_preimage.rs
- src/node94-consensus-admission/tests/block_preimage.rs
- Minimal Cargo.toml/Cargo.lock/lib.rs/README.md integration.

All collector/verifier/oracle/protocol artifacts are task-local. The ordinary ELF/FDE parser dependencies and pure existing Keccak arithmetic are bound to baseline hashes. The static native exporter reuses reviewed author-written scaffolding from1467 (evidence.py SHA009148327825191fc27f8e203625148c205d10b3d03b1f9f70fb232564c1dbce), retained here independently; no file from that pending packet is read at runtime.

Before Rust, freeze proof, source plan, protocol, dependencies, all scope/obligation records, independent mathematical oracle and byte/digest expectations. Record source-path absence and UTC separately; never restamp a later source correction as pre-code. Parent independently regenerates the corpus and reads native obligations before the code gate.

After the gate: only authored Rust is compiled/run with pinned1.94.1 offline/locked in both profiles. An input-only client uses the real Cargo library; the comparator alone receives expected bytes/digests. Required compiling mutants distinguish wrong tag, clamped/raw/mis-zigzag time, truncating negative-year division, wrong epoch, transaction/QC order, missing votes, absent/present-empty TC, timeout signature placement, raw65 signature, active/inactive signature bytes and padding. Finite comparisons supplement the manual contract; no target execution/emulation, target compiler equality, full suite or full consensus completion is implied.
