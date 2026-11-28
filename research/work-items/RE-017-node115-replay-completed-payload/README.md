# RE-017 #115 completed reader bytes into the replay wire codec

This introduces an [offline adapter](../../../src/node115-replay-completed-payload/README.md) for the selected producer's handoff after the reader has finished collecting bytes. It composes the existing size-prefixed LZ4 and Block-or-Tx codecs and uses the selected startup limit for both. A caller can now exercise both receive modes without needing a live peer or the captured async runtime.

| Prior observation | Applied here |
| --- | --- |
| [Ordinary reader return](../RE-017-node115-replay-reader-buffer/README.md) | The decoder sees the completed buffer directly. |
| [Compressed reader return](../RE-017-node115-replay-compressed-input/README.md) | The LZ4 adapter's actual returned length supplies the decoder span. Its declared capacity may differ from that length. |
| [Initial reader limit](../RE-017-node115-replay-reader-limit-origin/README.md) | The initialized 10,000,000 word supplies both downstream limits on this path. |
| [Block-or-Tx codec](../RE-017-node115-replay-wire-payload-codec/README.md) | The codec reads a prefix with one cumulative budget and returns typed payloads. |

The integration runs an ordinary and a compressed version of each synthetic Block and Tx prefix through the same API. The Tx fixture declares capacity 20, decompresses to 6 bytes and consumes 5 at the replay boundary. The Block fixture preserves a present, empty attachment vector in both modes. The tests use the existing literal encoder only to build local fixture data.

The API takes an already selected read mode and complete bytes. It reports a host-side consumed count and preserves the distinction between compression and payload decode results. Header acquisition, scheduling, slot ownership, Block gate acceptance, real checkpoint provenance and root validation remain separate tasks.

## Offline verification

From the repository root run:

```sh
python3 -B research/work-items/RE-017-node115-replay-completed-payload/verify.py
cargo test --locked --offline --manifest-path src/node115-replay-completed-payload/Cargo.toml
```

See [raw output](offline-log.txt) and [the selected ELF witnesses](windows.txt).
