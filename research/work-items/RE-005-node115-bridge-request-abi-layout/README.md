# Node #115 tag-5 bridge request ABI layout

- Component ID: bridge / serialization
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`; public-contract comparison lead pinned at `d7e66aa751ffbd19bfd2b90fd5d9a3d8f32d99ee`
- Claim status: static observations; ABI field-name mapping and resulting canonical encoding are an evidence-backed reconstruction, not a runtime observation
- Scope included and excluded: the five tag-5 descriptors, their type normalization, head/tail sizing, word writes, dynamic label tail, and the resulting 224-byte serialized layout. Excludes execution of the captured node, bridge digest/sponge algorithm, signature semantics, and caller authorization.

## Reproduce

From repository root, with GNU binutils objdump 2.47.20260726 and Rust 1.95.0:

```sh
python3 research/work-items/RE-005-node115-bridge-request-abi-layout/verify.py --target artifacts/node/115/hl-node
objdump -d --start-address=0x169dcc0 --stop-address=0x169de5b artifacts/node/115/hl-node
objdump -d --start-address=0x169e350 --stop-address=0x169e59b artifacts/node/115/hl-node
objdump -d --start-address=0x169df80 --stop-address=0x169e1c4 artifacts/node/115/hl-node
objdump -d --start-address=0x169de60 --stop-address=0x169df77 artifacts/node/115/hl-node
cargo test --offline --manifest-path src/node115-bridge-request-abi/Cargo.toml
```

All inspection is static. The verifier authenticates the full target digest, exact FDE extents, selected instruction bytes, relative jump-table destinations and the encoder relocation. The implementation tests synthetic byte values; they do not execute or differentially compare the native binary.

`raw-disasm.txt` retains the full disassembly for all nine selected FDEs. The verifier and raw windows require only offline local analysis tools.

## Evidence

The tag-5 producer's complete FDE is `0x44e96a0..0x44e9835`. It constructs five 0x28-byte descriptor records with raw tags `[6, 0, 0, 4, 4]`, and calls encoder slot `0x64e0140`, relocated to `0x169e350`. The existing [producer packet](../RE-005-node115-bridge-input-producers/README.md) pins the literal construction: the 16-byte prefix `requestWithdrawa` plus final byte `l`, yielding the 17-byte string `requestWithdrawal`.

`0x169dcc0` normalizes raw tag 0 and raw tag 4 into a one-item tag-0 wrapper. Raw tag 6 becomes tag 2, retains the descriptor pointer, and sets the wrapped block count to `ceil(length/32)+1`. With the observed label length 17, this count is two. The head-size helper returns 32 bytes for each normalized tag-0 or tag-2 item; five descriptors therefore account for a 160-byte head. The tail-size helper returns zero for tag 0 and `32 * block_count` for tag 2, so the sole dynamic string contributes a 64-byte tail.

The writer's type-2 head path writes the current tail offset as a big-endian 32-bit value at the end of a zeroed 32-byte word. The initial tail offset is the 160-byte head size, so the dynamic pointer word is `0xa0`. The tag-0 path delegates each original token to `0x169df80`: the two raw 20-byte values become twelve zero bytes followed by 20 source bytes; the two tag-4 values become four qwords in reversed order after byte-swapping, which for the caller's populated qword yields 24 zero bytes followed by its big-endian 64-bit value.

In the tail pass, normalized tag 2 dispatches the original tag-6 token to `0x169df80`, which calls `0x169de60` with its data pointer and length. That helper appends one zero-prefixed 32-byte length word and `ceil(17/32)=1` 32-byte data word containing the label and 15 zero pad bytes. Thus the reconstructed byte layout is five head words followed by two string-tail words: `5*32 + 2*32 = 224` bytes. The [independent Rust model](../../../src/node115-bridge-request-abi/README.md) emits exactly this shape for supplied 20-byte and 64-bit values.

The observed widths and byte transformations support the tuple shape. Mapping the two 20-byte values to addresses and the two qwords to particular public argument names is inferred by comparison with the pinned public bridge contract; that reference is unlicensed and used as a naming/shape lead only. No contract code is copied. The node bytes alone do not prove runtime reachability or the final digest algorithm.

## Implementation and comparison

`src/node115-bridge-request-abi` independently implements the selected 224-byte layout without dependencies or unsafe code. Four tests cover the dynamic offset and tail, all 40 fixed-width input byte positions, big-endian scalar placement, and zero-input behavior. No output from executing the captured binary is available or claimed. The native allocator's over-allocation and vector capacity are outside the model; only the serialized bytes are represented.

## Results and limitations

The verifier binds nine exact FDEs, 51 instruction-byte facts, ten selected relative switch-table entries, and one encoder relocation to the authentic #115 binary. One-byte corruption of a tag anchor is rejected. The calculated head/tail dimensions match the independent encoder's constants and tested output length. No completion gate is requested. Still unknown: concrete caller values, live reachability, exact semantic names independent of the contract comparison, and the digest/sponge result. Next question: establish the relation between these 224 bytes and the caller's finalized 32-byte output without claiming signing or authorization behavior.
