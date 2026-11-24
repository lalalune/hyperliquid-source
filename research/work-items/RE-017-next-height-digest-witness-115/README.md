# Reading an expected digest at the successor of a checkpoint height

For `qcp-expected-root-provenance`, this packet supplies a bounded offline input contract. A separately sourced `abci_digest_quorum` line provides a candidate expected digest. A local `abci_hashes` line supplies the independently read comparison operand. Given checkpoint height H, the fixture requires an exact record at H+1 on **both** sides. This is a condition imposed by the experiment. The native comparator searches by the incoming row's key and can skip missing history.

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`. The new [Rust writer](../../../src/node115-digest-reference-handoff/quorum-line/src/lib.rs) emits the quorum line from the existing selected reference row. A reader can now feed that exact output to the packet's offline comparison. It uses the selected writer's compact JSON field order, the decimal height, a quoted lowercase 32-byte hex digest with leading zeros, and the terminating newline.

## Producer and operand identity

| Source | Value to read | Evidence in #115 |
| --- | --- | --- |
| Witness run, incoming `abci_digest_quorum` | `height` and `d` | The compact row's +0 and +0x48 reach `0x4e3a020` before the local lookup. The [quorum writer](../RE-008-abci-digest-quorum-log-115/README.md) emits them from record +0x20 and +0 respectively. [The handoff](../RE-017-node115-digest-reference-handoff/README.md) traces the selected tracker row. |
| Observed run, computed `abci_hashes` | `height` and `abci_digest` | The [computed-record writer](../RE-008-abci-hashes-log-115/README.md) reads distinct fields at +8 and +0x10. The separate `exchange_abci_hash` field has its own tree representation and is ignored by this comparison. |

The two record constructors pass different height addresses to the same field writer at `0x537d62c` and `0x537d7fc`. The writer at `0x5077210` loads the full qword, appends a colon, and calls `0x50fc010` with scratch storage. That helper uses a 20-digit buffer, a 10,000 threshold and a 200-byte table spelling 00 through 99. The selected caller appends the returned decimal bytes. `verify_height.py` checks the two height-field joins and the digit table directly against the pinned ELF, complementing the two existing writer verifiers.

## Provenance and stopping conditions

For a real comparison, retain the externally obtained witness log and its independently provided SHA-256, the origin/run that supplied it, and the corresponding network or branch identity. Record the restored H, the local run identity and its log's SHA-256 separately. Both files must refer to the same history through H+1. The checker verifies file content against the supplied digests and checks the row height. Operator identity, branch identity, vote authority and independence of acquisition require evidence outside these two log formats. A readable file or a different pathname cannot establish those facts.

The bundled records are synthetic. They exercise the file contract without asserting a canonical block digest:

| Input | Origin | SHA-256 |
| --- | --- | --- |
| `fixtures/witness.jsonl` | Hand-encoded byte expectation for the height-41 row with digest `[0x11; 32]` from the pre-existing [#5157 contract](../../../src/node115-digest-reference-handoff/tests/contract.rs). At the stated base that source file hashes to `6d1c9cab6d8a87c68141f16b40e4601ca5cc46902694c5a8df856a8f513b0655`. The new Rust writer is tested against this frozen line. | `c3644ff7f6d208cdf646696c60446243ef8282a03b099af6d9676b8b4b49a6c1` |
| `fixtures/local.jsonl` | Two hand-authored computed-line examples with distinct exchange tree values. The controlled case sets the height-41 computed digest to the expected value. Height 40 is a decoy. | `639b08de6ad69213f1148035227d6abd02991c4031d41ec11b5b567158eebef4` |

The underlying root of a live history and a genuine independently observed pair remain unestablished. The fixtures contain no captured state transition or signatures. No pilot acceptance state or component gate changes.

## Reproduce

From the repository root:

```sh
p=research/work-items/RE-017-next-height-digest-witness-115
python3 -B "$p/verify_height.py"
python3 -B tools/abci_digest_quorum_log_115.py --check
python3 -B tools/abci_hashes_log_115.py --check
cargo test --offline --locked --manifest-path src/node115-digest-reference-handoff/quorum-line/Cargo.toml
python3 -B -m unittest discover -v -s "$p" -p test_compare.py
python3 -B "$p/compare.py" 40 \
  "$p/fixtures/witness.jsonl" c3644ff7f6d208cdf646696c60446243ef8282a03b099af6d9676b8b4b49a6c1 \
  "$p/fixtures/local.jsonl" 639b08de6ad69213f1148035227d6abd02991c4031d41ec11b5b567158eebef4
```

The example returns `equal` at height 41. Exit status 1 identifies a comparison with differing digests. Exit status 2 identifies insufficient or malformed input, including a missing successor, conflicted records at the requested height, wrong file digest or the same file for both roles. Identical reports at one height agree. The tests keep the exchange hash equal to the witness while changing each byte in the local digest independently.
