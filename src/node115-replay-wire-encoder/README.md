# Node #115 replay wire encoder

`encode_replay_payload` emits the Block-or-Tx prefix from the existing
`node115-client-block-success` types. It does not add transport framing
or compression.

See the [offline evidence](../../research/work-items/RE-017-node115-replay-wire-writer/README.md).
