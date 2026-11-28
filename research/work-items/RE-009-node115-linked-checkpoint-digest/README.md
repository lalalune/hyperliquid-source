# RE-009 Node #115 linked checkpoint digest implementation

The existing state-root reducer computes a raw ABCI digest. The hardfork and checkpoint paths also emit a linked L1 digest that binds the raw digest to serialized state bytes. `compute_linked_l1_digest` makes this second operation available in the existing `node115-abci` hash API.

- Component: `abci` / `storage`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `c42e4eebf847462db32c934af4140a346ebba310`.
- Method: LLVM objdump 23.1.4, Intel syntax, ELF virtual addresses. The new verifier reads the pinned ELF and checks the selected producer/consumer boundaries without executing captured code.

## Exact input span and digest order

For the selected hardfork worker route, the serializer closure `0x4e4b860` initializes a vector descriptor at stack `+0x70` and passes it through the serializer configuration to `0x5480950`. On the selected named MessagePack path, configuration byte `+0xb` is 1. The success result returns the vector pointer and length as qwords `+8` and `+0x10`. For this implementation the caller supplies those bytes unchanged. It does not regenerate the state's serialization.

The direct capture adapter `0x4e36140` forwards the serializer pointer and length as its own result `+8` and `+0x10`, before the worker stores them as the first two argument words of the digest call. The enclosing capture's second descriptor bytes are outside this span. The raw digest becomes argument `+0x10`. A separate pointer to height metadata is at `+0x18`.

The selected `0x457cf60` hash path makes one BLAKE3 update over the state pointer and length. It then initializes another hasher and updates it with the 32-byte result followed by the 32 raw ABCI digest bytes. The separate metadata pointer is outside both updates. Any height already encoded in the state bytes remains part of the first update. The resulting 32 bytes are `BLAKE3(BLAKE3(serialized_state) || abci_digest)`. The verifier checks both relocation-backed BLAKE3 calls and the ABI path getting the actual byte span to them, building on the [formula packet](../RE-008-l1-hash-input-115/README.md) and [linked state packet](../RE-017-abci-linked-commit-115/README.md).

## Offline verification

```sh
python3 -B research/work-items/RE-009-node115-linked-checkpoint-digest/verify.py
cargo test --locked --offline --manifest-path src/node115-abci/Cargo.toml
```

The new Rust tests use independently generated BLAKE3 1.0.8 vectors for empty input, a synthetic nine-byte MessagePack map, and 1,025 bytes across a chunk boundary. The tests require the actual pointer/length behavior through a slice with extra backing bytes. They distinguish reversed digest order and an extra height suffix. Run `python3 -B research/work-items/RE-009-node115-linked-checkpoint-digest/reference.py` with that optional Python package to regenerate the vectors. The verifier rejects altered operand bytes for length and selecting the digest metadata pointer. The [offline log](offline-log.txt) records the independent reference values and the Rust test output. The [instruction windows](windows.txt) record the target evidence.

A successful test establishes the digest composition for supplied inputs. It does not recover a real checkpoint's serialized bytes, prove their provenance, or substitute this digest for the raw ABCI root.
