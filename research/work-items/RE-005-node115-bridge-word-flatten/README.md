# Node #115 bridge word flatten and digest handoff

Partial HL115-067. Target SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Linked virtual addresses, static inspection only; no captured execution or emulation.

Merged #2271 identifies the selected bridge request and digest handoff; #3265 establishes the two tags, normalization, head/tail accounting and conditional word views, but leaves flattening and ownership opaque. #3409 binds the growth slot in related ABI encoding. This packet follows that selected path through the word backing, flatten helper, and caller's digest input and deallocation. #1067 concerns node #94 and does not establish the #115 digest algorithm.

The selected 52-byte input produces two class-zero words: twelve zero bytes followed by input bytes 0..20, then input bytes 20..52. As #3265 established, each contributes 32 head units and zero tail units. `0x169e350` uses total 64 as a word capacity and requests 64*32 = 2,048 bytes for intermediate word storage. The two word writes fit without invoking the growth helper; its growth behavior is not claimed as executed.

The flatten descriptor supplied to `0x169bf30` has inactive outer fragments and an active span of the two written words. The helper computes a 64-byte flattened length, requests that many bytes, copies each 32-byte word in order, and releases the intermediate allocation with its capacity converted to bytes. It returns the separate allocation as capacity 64, pointer, length 64. Ordinary successful allocation and copy, valid descriptor invariants and stable input are premises; allocation failure, unwinding and unrelated token classes are outside scope.

`0x4526e40` reads the returned pointer and length and passes them to `0x64e0148 -> 0x5cda910`. It then requests 32 output bytes via `0x64e0150 -> 0x5cdad40` and releases the returned input allocation using its capacity. This establishes the selected digest input and its lifetime through the normal call, not the digest algorithm or resulting digest bytes. In particular, no #94 implementation is imported as #115 proof.

`src/node115-bridge-word-flatten` independently builds an owned 64-byte preimage from the two input slices. Its returned array is a source-owned representation; the reported native allocation requests are observations, not a claim that Rust uses the same allocator or capacity. Three tests cover all 52 single-byte positions, explicit boundary bytes, input independence, and the distinction between 2,048-byte intermediate allocation and 64-byte returned payload.

```sh
python3 research/work-items/RE-005-node115-bridge-word-flatten/verify.py --target artifacts/node/115/hl-node
cargo test --offline --manifest-path src/node115-bridge-word-flatten/Cargo.toml
```

The verifier requires Capstone 5.0.7 and authenticates the complete target and FDEs. Seven selected windows contain 3,304 bytes and 807 instructions; 64 facts and twelve semantic byte/relocation controls are checked. These are static checks, not execution equivalence. Complete signing, digest identity and other bridge operations remain open; no completion gate changes. New code and evidence are MIT.
