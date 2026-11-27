# RE-009: bounded offline checkpoint-to-replay-to-root-validation fixture

- Component ID: `storage` / `abci` (`qcp-checkpoint-replay-root-fixture`, issue #3923 / pilot #5391)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Scope: smallest independently checked offline fixture joining ONLY the four reviewed pilot contracts over synthetic, SHA-256-hashed inputs. No captured binary execution, no live chain data or signing, and no full `storage`/`abci` component acceptance claim.

## Connected prerequisite contracts

| Pilot question | Prerequisite packet | Contract connected in this fixture |
| --- | --- | --- |
| `qcp-first-replay-key` | `RE-017-node115-replay-key-source` | Restored height `[S+0x28] = H`, round `[S+0x30] = R`, loader increment `[S+0x18]`, copied round `[S+0x20]`, and replay initializer `+0x9a0`/`+0x9a8` with no arithmetic. |
| `qcp-root-selector` | `RE-009-node115-root-digest-selector` | Exact 4-stage repeated-read selector `0x160bee0` over `.bss` cell `0x6500098` returning selector byte `1..=4`. |
| `qcp-root-cell-writer` | `RE-009-node115-root-digest-cell-writer` | Fallback writer `0x5cadd50` writing 3 qwords at `0x6500098 + {0, 8, 16}` (`r13 \| rdi` at `+0`) while returning `r13`. |
| `qcp-expected-root-provenance` | `RE-009-node115-expected-root-provenance` | Single-owner `0x5a04e40` flow (`ctx + 0x450`): `H -> H+1` saturating increment at `0x54838d3..0x54838e5`, external `0xdd` vote ingestion into `S + 0x3e50`, two-gate false-to-true selection, drain via `0x5afa030`, sink-before-comparison (`ctx + 0x280` then `ctx + 0x400`), and post-comparison local root write (`0x5a07ec0 -> 0x5a03fa0`). |

## Synthetic fixture and implementation

- **`fixture.json`**: Names and SHA-256-hashes all 6 synthetic inputs (`checkpoint`, `first_replay_block`, `root_selector_input`, `support_context`, `registry`, `vote_replay_block`), explicitly tagging local root production (`local_post_comparison_ctx_0x400`) separately from external vote provenance (`external_action_0xdd_synthetic`).
- **`src/node115-abci-checkpoint-replay-fixture`**: Independent Rust integration crate linking `node115-checkpoint-discovery`, `node115-digest-vote-admission`, `node115-digest-support-gate`, and `node115-digest-reference-handoff`, with integration tests covering positive match, single-byte mismatch + sink-before-comparison ordering, same-block comparison-before-local-write isolation, all 4 root-selector arms + unstable-cell repeated reads, and restore/admission/height-limit negative controls.

## Reproduce

```sh
python3 research/work-items/RE-009-node115-checkpoint-replay-root-fixture/verify.py --self-test
python3 -m unittest tests.test_checkpoint_replay_root_fixture_115
(cd research/work-items/RE-009-node115-checkpoint-replay-root-fixture && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/storage-abci \
  cargo test --offline --manifest-path src/node115-abci-checkpoint-replay-fixture/Cargo.toml
```

## Unresolved boundaries preserved

- ECDSA signature recovery (`0x64e0ad8`), timer-delay configuration (`tracker + 0x88`), alternate flat/wrapped timer path (`0x57f1690`), CPUID feature semantics and concurrent cell reads (`0x6500098`), live-chain canonical root trust, captured execution, and full `storage`/`abci` component acceptance gates remain explicitly out of scope.
