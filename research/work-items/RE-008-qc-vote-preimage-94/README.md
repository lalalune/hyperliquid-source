# RE-008: QC-vote signing preimage, node94

The selected variant1 of `0x454c050` includes the signer20 **before** three
variable-width integers and the block hash32. This closes one digest-input gap
in the existing consensus component and supersedes an unsupported signer-exclusion
sentence in the old vote-path packet. It does not establish an authentication bug.

```text
"Hyperliquid Consensus Payload" || 01 || signer20
|| VLE64(version) || VLE64(start_round) || VLE64(round) || block_hash32
```

The preimage is85..109 bytes. [PROOF.md](PROOF.md) gives the full selected
measure/write/caller chain and memory/call premises. Source APIs
`qc_vote_preimage(&Qc, ValidatorAddress)` and `qc_vote_digest` are added to
`src/node94-consensus-admission`; the explicit signer need not occur in
`qc.votes`. Votes/signatures are ignored by this encoder. Membership and
authentication remain the caller's separate operations.

- Component: RE-008, partial reconstruction; no progress gate changed.
- Target: `artifacts/node/94/hl-node`,91,774,280 bytes,
  SHA256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source/research base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Coordinates: linked ELF VAs, half-open full FDE ranges;18 ranges/10,532 bytes/
  2,495 normalized instruction rows. Context is not whole-component coverage.
- MIT implementation uses the real existing local `hl-bincode-varint` scalar
  encoder and `node94-action-signable` Keccak implementation. No unlicensed
  reference code was copied and no unmerged bincode-wrapper API is required.

## Results and useful boundaries

| Check | Actual result |
| --- | --- |
| Full GNU/LLVM exports and FDE/ELF bindings |18 ranges agree; no omitted/masked bytes; only standalone LLVM LOCK rows joined |
| Static verifier, ordinary and Python-O |97 negative controls; two fresh exports equal retained per run; results identical |
| Pre-Rust frozen expectations |783 cases; independent field/threshold preimages and mathematical Keccak fixtures |
| Rust1.94.1 debug and release |47 component tests/profile;783/783 frozen comparisons/profile |
| Compiled omission/order/endian/domain mutants |All six rejected, counts below |
| Source formatting, Clippy all targets, diff check |Passed; see VALIDATION.md |

Compiled mutants mismatch783/783 for omitted signer, extra `consensus msg`,
and tag0;782/783 for hash before integers (the allzero case commutes);
565/783 for big-endian integer payloads;269/783 for encoding250 as FBFA00.
These are actual compiled source changes in temporary copies of the three
real components. They are not captured-code mutations or equivalence proofs.

The existing Keccak identity is credited to
[RE-009-app-hash-builder-94](../RE-009-app-hash-builder-94/README.md#hash-core) and
[RE-005-action-signable-94](../RE-005-action-signable-94/README.md).
The new proof binds this selected input to the shared core's single-block path.
It does not newly prove every permutation lane equation. The source hash wrapper
is Keccak-256; its correspondence to the native output is conditional on that
credited shared-core identification.

The older [vote-path packet](../RE-008-vote-timeout-path-94/README.md) and
[admission packet](../RE-008-block-admission-94/README.md) explicitly stubbed the
digest with SHA256 fixture fields. Their outputs are not real digest oracles.
Only the old README's unsupported field-coverage sentence is annotated here;
its generator, fixtures, gates and captured evaluator are unchanged.

## Reproduce

Python standard library, GNU objdump2.47.20260726, Apple LLVM21.0.0 and
Rust1.94.1 were used. Both disassemblers receive the same authenticated,
private read-only ELF snapshot; it is never executed. Exports are version
sensitive; provider path overrides do not silently normalize textual differences.

From repository root, with fresh output directories:

```sh
python3 research/work-items/RE-008-qc-vote-preimage-94/verify.py --out work/qc-vote-check.json
python3 -O research/work-items/RE-008-qc-vote-preimage-94/verify.py --out work/qc-vote-check-O.json
python3 research/work-items/RE-008-qc-vote-preimage-94/evidence.py --out work/qc-vote-native
python3 research/work-items/RE-008-qc-vote-preimage-94/build.py \
  --cargo "$(rustup which --toolchain 1.94.1 cargo)" \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --rustdoc "$(rustup which --toolchain 1.94.1 rustdoc)" \
  --out work/qc-vote-rust
(cd research/work-items/RE-008-qc-vote-preimage-94 && shasum -a 256 -c MANIFEST.sha256)
```

`evidence.py` and `verify.py` accept `--gnu`/`--llvm`.
`build.py` checks the real three-crate graph, absent build hooks/Cargo configs,
and pinned compiler versions, then uses offline/locked Cargo. The existing
integration test's only subprocess is a target-file shasum; it does not run
the target. Broad `make test` and captured evaluators were not run.

## Evidence map and limits

`PRE-RUST-FREEZE.json` records the derivation before the new Rust.
`POST-FREEZE-NORMALIZATION.json` records removal of one final blank line from
three frozen text files; `verify.freeze()` reconstructs and checks the exact old
bytes. Expected vectors and native exports never changed. `vectors.tsv.gz`
holds all783 expectations; `corpus.py` regenerates them without any instruction
interpreter. GNU full exports are readable in `observed/`, LLVM full exports
are deterministically compressed. Compact `records.json` binds all full ranges.
`pins.json` selects49 witnesses; verifier adds explicit tag1 and round-table
checks without modifying the frozen derivation.

`rust-validation/` retains raw driver outputs (compressed), compiler/test logs,
source hashes, mutant outcomes and before/after build results. Only ephemeral
paths are normalized in command logs. Debug/release output bytes are identical.
No target output was executed or observed dynamically.

Normal successful calls and the disjoint/stable memory premises matter,
especially across timing/prelude and cleanup calls. No claim covers malformed
pointers/tags, allocation failure, LSDA/unwind, liveness, otherfour digest
variants, proposal scheduling, signature generation/recovery, or end-to-end
authentication. No private key, chain action or network service is involved.
