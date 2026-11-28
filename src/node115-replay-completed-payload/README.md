# Node115 completed replay payload

`decode_completed_payload` takes a completed plaintext or size-prefixed LZ4
buffer and returns the replay payload prefix with its decoder span, consumed
count and charge. The limit is the value observed for the selected initial
producer. This library performs local byte decoding only. See the
[RE-017 evidence](../../research/work-items/RE-017-node115-replay-completed-payload/README.md).
