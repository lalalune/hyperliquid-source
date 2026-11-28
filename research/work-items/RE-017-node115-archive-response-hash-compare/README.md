# RE-017 · Compare a node115 archive response Hash with reconstructed Full outcomes

An archive row with `resps.Hash` can be compared against a separately obtained ordered Full response for the same block. The selected replay worker computes the Hash from its result vector. The [result fingerprint packet](../RE-017-abci-result-digest-115/README.md) traces the worker's tag-1 output, vector encoding and sponge. The [result variants packet](../RE-017-abci-res-variants-115/README.md) identifies the named result wrappers and selected nested status formats. The [archive response packet](../RE-017-node115-replica-response-json/README.md) pins the tag-1 `Hash` field.

The worker hash routine initializes its writer with bytes `00 04 00 01` at writer offset `+8`, so `+0xb` selects the named form for the action responses. The ordered outer result vector writes each row as a pair consisting of the 32-byte digest rendered as a lowercase `0x` string and an array of responses. Each selected response is a named two-field map, `user` before `res`. A missing user encodes as MessagePack nil. A present user encodes as a 42-byte string. The resulting named MessagePack bytes feed the selected Keccak-256 sponge. The worker's tag-1 output reaches the JSON `resps.Hash` variant on the existing selected sink path.

`compare.py` reuses the existing modeled result writer for errors of at most 255 UTF-8 bytes, default successes, and cancel lists with fewer than 16 selected success or text-error statuses. Other results produce a located unsupported-outcome response before any equality result. The caller supplies an independently produced Full response and establishes that both inputs describe the same block. The comparison preserves the exact supplied group and individual response order, including empty arrays. An archive response fingerprint is distinct from a checkpoint or post-block state root.

The fixture is synthetic. Its literal 279-byte expected preimage exercises a present user, a missing user, and an empty group. Separate controls test a cancel response, an empty vector, and reordered groups and entries. The static verifier checks the named writer configuration and selected producer and serializer paths. The offline run also compares its synthetic digest against the existing independent Rust Keccak implementation.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

From the repository root:

```sh
packet=research/work-items/RE-017-node115-archive-response-hash-compare
python3 -B "$packet/verify.py"
python3 -B "$packet/compare.py" "$packet/archive-synthetic.jsonl" "$packet/local-full.json"

scratch=$(mktemp -d)
python3 -B "$packet/verify.py" --preimage "$scratch/preimage.msgpack"
rustc --edition 2021 --crate-type lib --crate-name reference_hash \
  src/l1-shared/src/utils.rs -o "$scratch/libreference_hash.rlib"
rustc --edition 2021 --extern "reference_hash=$scratch/libreference_hash.rlib" \
  "$packet/reference.rs" -o "$scratch/reference"
"$scratch/reference" < "$scratch/preimage.msgpack"
```

The [raw offline output](offline-log.txt) records the verifier, matching archive comparison, and independent hash.
