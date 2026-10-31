# Beginning reverse engineering

## First session

```sh
./scripts/setup.sh
make doctor
make verify test
make catalogue-check
make index
make fde-index
python3 tools/ghidra_plan.py --release 94
```

`make doctor` reads tool versions and installation paths; it does not launch
Ghidra, Docker, a node or a visor. `make index` verifies each node digest and
writes ordered unwind starts to `work/index/`. These are address-discovery
leads: the next indexed start is an upper bound, not a decoded function size.
No component ownership or function equivalence follows from this index.
`make fde-index` decodes every `.eh_frame` FDE into `work/index/` start/end
extents, checks them against that index and lists uncovered `.text` gaps. An
FDE extent is still not a validated function boundary; see
[RE-001 FDE extents](../research/work-items/RE-001-fde-extents/README.md).

`ghidra_plan.py` prints a static import command for a fresh, digest-named
project under `work/ghidra/`. Set `GHIDRA_HOME` when Ghidra is not discovered.
On Windows it prints a PowerShell plan for `analyzeHeadless.bat`; on POSIX
hosts it retains the shell plan for `analyzeHeadless`.
Run the printed command when ready for the substantial import; save the tool
version, options, log and completeness of analysis. The 1,800-second per-file
analysis budget may produce partial results. Reuse that project for later
queries; do not mistake a timeout or partial database for full coverage.
The wrapper refuses an existing project so a repeat import cannot overwrite it.

Inspect a short interval before requesting whole-program pseudocode:

```sh
# Example address is only a can1357 lead, not a validated function boundary.
LLVM_OBJDUMP="$(brew --prefix llvm)/bin/llvm-objdump"
"$LLVM_OBJDUMP" --disassemble --start-address=0x2209d40 --stop-address=0x2209e40 \
  artifacts/node/94/hl-node > work/abci-seed.asm
```

The standard installed Ghidra supports x86-64. The sBPF extension used for
Pump.fun is not needed for this target. If using REA, select the exact node
artifact and a native Ghidra/IDA provider, retain its evidence records and
close the session when finished. This repo does not change global MCP/client
configuration or assume an REA server is connected.

## What exists now

- Hash-pinned signed binaries, a public signing key, and pinned reference repos.
- Reproducible inventories and the corrected 1,452-item literal classification.
- A component catalogue covering all 237 reference Rust files (232 first-party
  paths plus five bincode-fork files) and the 173 allowlisted #94 embedded
  source paths. Three #94 paths are absent from the reference; 62 first-party
  reference paths are additional splits/helpers.
- Imported comment addresses collected in research/catalogue/seed-candidates.json.
  Executable-section membership is only a coarse filter. Every seed still needs
  disassembly, cross-reference and function-boundary validation.
- A fail-closed unwind indexer for the captured nodes' exact ELF/header encoding.
- A fail-closed FDE extent decoder, cross-checked against GNU readelf for both nodes.

The local preflight on 2026-10-28 found Python, Git LFS, GPG, ripgrep,
LLVM 22.1.4, Java 21.0.10, Ghidra 12.1.4 and both Rust versions. That describes
this workstation only. Docker was unavailable during initialization; the
container definition remains unbuilt. Ghidra's no-argument headless launcher was also checked successfully; no target
was imported. Run doctor on each contributor machine.
The retained [readiness packet](../research/work-items/RE-000-readiness/README.md)
records checks, input identities and limits.

## Required recovery before a faithful build

| Area | Known evidence | Needed next |
| --- | --- | --- |
| Target identities | Manifest hashes and GPG signatures | Preserve release-specific binding in every packet |
| Compiler | #94 Rust 1.94.1; #115 Rust 1.95.0 | Exact Linux target/config, flags, features, allocator, panic/LTO/codegen settings |
| Linker/toolchain | #94 LLD 21.1.8 / clang 21.1.0-rc2; #115 LLD 22.1.2 / clang 22.1.0-rc2 | Matching toolchain artifacts and repeatable container/build image |
| Private workspace | Embedded paths and inferred modules | Cargo manifests, crate boundaries, module graph and feature set |
| Dependencies | Imported paths, dynamic libraries and #115 vendor/fork hints | Version locks and exact contents of private forks; absence of #94 vendor paths proves nothing |
| Serialization | Reference bincode_fork and signing/wire leads | Byte layouts, discriminants, endianness, lengths, signature domains and error behavior |
| Function ownership | Unwind starts and comment seeds | Real boundaries, callers/callees, data/vtable references and monomorph ownership |
| State and storage | ABCI/RocksDB/EVM source-path leads | Persisted schema, hashes, state transitions and offline replay fixtures |
| Equivalence | No accepted comparator or reconstructed component yet | Source builds, differential fixtures, corruption controls and byte/relocation comparison |

Inferred dependencies include Tokio, Serde, RocksDB and bincode from the
reference imports, and reth/revm/private HTTP forks from captured #115 paths.
REA static inspection found **no `.dep-v0` cargo-auditable dependency section**
in either binary. The complete records, including their limitations, are
[94](../research/rea/node-94-rust.json) and
[115](../research/rea/node-115-rust.json). Compiler path hashes are inference;
absence of the dependency section is not absence of dependencies.
These hints are not a Cargo.lock. Copy neither current registry versions nor
upstream HEAD into a claim of target provenance. Both node inventories list
libstdc++, OpenSSL 3, libgcc, libm, libc and the Linux dynamic loader.

## Working sequence

1. Pick one bounded question from TASKS.md and bind it to one artifact digest.
2. Validate an entrypoint and its immediate callers, data references and error
   exits. Keep observed instructions separate from inferred names/types.
3. Recover inputs, outputs, memory layout, arithmetic width, overflow and
   rounding behavior. Record unresolved indirect calls and shared helpers.
4. Write independent Rust only once enough semantics are known. Introduce a
   component Cargo project with a lockfile and exact build instructions then;
   do not make a synthetic root workspace look like recovered source.
5. Build twice and compare the stated scope. Preserve raw bytes before any
   normalization. Exercise invalid/truncated inputs and boundary cases with
   target-grounded expectations; execution needs the isolated harness approval.
6. Submit the evidence packet and update a progress gate only when its complete
   scope is supported. Keep outstanding gaps explicit.

Begin with fixed-point arithmetic and serialization leaves. They constrain
exchange/risk recovery and are small enough for meaningful proofs. Study
consensus, storage and EVM alongside them, but do not start with a whole-node
rewrite based on unverified reference types.
