# Node #115 bridge `requestWithdrawal` token path

- Component ID: bridge / serialization
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`; pinned `upstream/contracts` submodule `d7e66aa751ffbd19bfd2b90fd5d9a3d8f32d99ee` (comparison lead only)
- Claim status: observations; public field-name correlation remains inference
- Scope included and excluded: the five token descriptors prepared by the tag-5 producer at `0x44e96a0`, dispatch in `0x169df80`, and the exact normalization behaviors selected by tags 0, 4, and 6. Excludes runtime reachability, complete general-purpose ABI encoder semantics, source-level types, and digest/signing claims.

## Reproduce

From repository root with GNU binutils objdump 2.47.20260726:

```sh
python3 research/work-items/RE-005-node115-bridge-request-token-path/verify.py --target artifacts/node/115/hl-node
objdump -d --start-address=0x44e96a0 --stop-address=0x44e9835 artifacts/node/115/hl-node
objdump -d --start-address=0x169df80 --stop-address=0x169e1c4 artifacts/node/115/hl-node
objdump -d --start-address=0x169e1d0 --stop-address=0x169e342 artifacts/node/115/hl-node
```

The packet retains full raw disassembly for the selected FDEs in `raw-disasm.txt`. Static inspection only; no captured code execution, emulation, signing, or network access. Addresses are linked virtual addresses. `verify.py` authenticates the full ELF digest, checks exact FDE extents, selected original instruction bytes, the relative jump table, the relocation, and a byte-mutation negative control.

## Evidence

The complete FDE for the token producer is `0x44e96a0..0x44e9835`. It allocates and zeroes a `0xc8`-byte record, writes tag byte 6 at record offset `0`, then writes type bytes at offsets `0x28`, `0x50`, `0x78`, and `0xa0` with values 0, 0, 4, and 4. It passes a vector descriptor with length 5, data pointer to the record, and element count 5 to indirect slot `0x64e0140`. Thus the observed descriptor tag sequence is `[6, 0, 0, 4, 4]`; the record's first byte and each 0x28-byte token stride are visible directly in the call preparation.

The relocation at `0x64e0140` resolves to `0x169e350`. The selected serializer path normalizes each input descriptor through `0x169c190` / `0x169dcc0` and appends the normalized vector using `0x169e1d0`. These helper boundaries and the selected caller FDE are digest-bound by the verifier. The tag dispatch table at `0x47b754` sends type 0 to `0x169e02c`, type 4 to `0x169dfd4`, and type 6 to `0x169dfb3`.

Observed normalization details:

- Type 0 reads the 16 bytes at token `+1` and the 32-bit value at `+0x11`, zero-initializes a 32-byte output word, then writes twelve zero bytes followed by those 20 input bytes. It does not itself establish a public semantic name for those bytes.
- Type 4 reads four qwords at token offsets `+8`, `+0x10`, `+0x18`, and `+0x20`, byte-swaps each qword, and stores them in reverse qword order into a 32-byte word.
- Type 6 reads qwords at token offsets `+0x10` and `+0x18` and tail-calls `0x169de60` with those values and the output buffer. The bounded packet does not claim the helper's complete byte/string encoding semantics.

The five observed tags therefore select one type-6 pointer/length path, two type-0 normalization paths, and two type-4 paths. This is consistent in shape with a label, two 20-byte values, and two 256-bit values, but assigning those public roles from the pinned `Bridge2.sol` reference is an inference, not a binary-proven type declaration. The reference is unlicensed and used only as a comparison lead; no source code is copied.

## Implementation and comparison

No Rust implementation or native behavior comparison is claimed. The packet records a static token-construction and normalization path only. No ABI output is synthesized from assumed field types.

## Results and limitations

The verifier requires the exact #115 ELF SHA-256 and exact recorded FDE extents. It also rejects a changed producer instruction byte. This validates the selected evidence anchors, not full encoder correctness or runtime behavior. No progress gate is requested. Unknowns include the originating public field names, the complete serializer's output semantics for all token classes, and whether this caller is reached in a live request. Next bounded question: prove how the type-4 32-byte word and type-0 20-byte word are emitted by `0x169e350` into the flattened output, preserving all other token classes as out of scope.
