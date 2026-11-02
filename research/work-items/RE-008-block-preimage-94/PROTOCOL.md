# Independent input frame and frozen expectations

This is a new test protocol, not the native ABI or network format. The client must receive only input frame hex plus an inert case ID. It must never receive the preimage, expected length, expected digest, semantic label or any expected-value file path.

Each frame is exactly, in order:
1. proposer20; block round LE64.
2. packed date LE signed32; seconds LE32; nanoseconds LE32.
3. transaction count LE32; that many raw32-byte hashes.
4. QC frame.
5. one option byte0/1; when1, TC round LE64, timeout count LE32, then timeout frames.
6. outer block signature72, included as an ignored-field adversary.

QC frame: version/start/round each LE64, hash32, vote count LE32, then each signer20 and signature72.

Timeout frame: signer20, round LE64, outer signature72, QC frame. This test-input order deliberately differs from the native nested serialization order (signature first); production receives typed values, not precomputed serialized fields.

The driver must reject trailing bytes, truncated fields and option bytes other than0/1. Counts are bounded by remaining frame bytes before allocating/looping. No expected metadata is parsed by the client.

`fixtures/vectors.tsv.gz` has case_id, input_hex, expected_preimage_length, complete_preimage_hex and digest_hex. Only the first two columns are supplied to the input client; remaining columns stay in the parent comparator. `cases.jsonl.gz` retains readable independent input values. `corpus.json` records case count, all-year arithmetic certificate and actual rate-boundary witnesses.

Expected values come from a pre-Rust pure value model. Time uses an independently generated400-year prefix partition, while the planned source uses a signed-floor closed equation. The source of scalar byte classes/order is the manual target proof; the oracle is not an independently observed target runtime. Digest arithmetic is the credited baseline MIT Keccak helper extracted by AST without importing its instruction evaluators. Its relationship to the native permutation remains conditional.

No giant synthetic slices or forced OOM are required. The finite corpus covers scalar and nested count thresholds within practical memory, all raw-year boundary families, ordinal0/511, unrestricted seconds/nanoseconds words, inactive flags/padding, nested TC/QC ordering, absent/present-empty options and complete136-byte rate boundaries. Symbolic/count/size proofs cover wider domains explicitly; tested finite counts do not stand in for those proofs.
