# Node115 completed replay payload

`decode_completed_payload` takes a completed plaintext or size-prefixed LZ4
buffer and returns the replay payload prefix with its decoder span, consumed
count and charge. The limit is the value observed for the selected initial
producer. This library performs local byte decoding only. See the
[RE-017 evidence](../../research/work-items/RE-017-node115-replay-completed-payload/README.md).

For a completed Block, use `DecodedPrefix::check_block_identity` with the
ordered pair supplied by startup. It returns the projected successor on a
match and the two observed words on a mismatch. Tx and decode errors have
their own outcomes. See the
[Block comparison evidence](../../research/work-items/RE-017-node115-completed-replay-block-gate/README.md).
