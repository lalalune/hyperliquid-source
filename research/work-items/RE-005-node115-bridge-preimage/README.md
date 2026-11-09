# Bridge builder: complete selected preimage and inner digest

This packet advances issue #3917 by closing the selected bridge builder's word append and flattening gap. Given the caller's already produced twenty-byte and thirty-two-byte fields, the builder returns a complete 64-byte buffer `zero12 || input20 || input32`. The Rust crate reconstructs that buffer and its bounded 32-byte inner digest. This is a partial bridge contribution: the fields' upstream meaning, full request schema, authorization and persistence remain unproved. Issue #3917 remains open; no acceptance gates change.

## Credited prerequisites and new evidence

`RE-005-bridge-static-framing-115` already identifies `0x4302cd0` and the selected tag0/tag1 normalization, class0/count1 descriptors, head/tail accounting and two word views. It explicitly leaves actual copy/growth/final flattening and the returned byte descriptor unclosed. This packet adds those selected normal-path joins through `0x169e1d0`, `0x169df80`, and `0x169bf30`, then follows the actual returned pointer/length into the digest caller `0x4526e40`.

`RE-001-node115-noop-preimage` and `RE-009-sponge-permutation-115` supply the previously established sponge/helper relation and independently authored MIT permutation. Their evidence is reused, with the selected 64-byte input path checked here. No captured instruction evaluator is run. The unchanged permutation source SHA-256 is `54d751f5d2366fdba907838d5980826b6fd48c3764adf338c55c13a950a6e0f8` and is checked by the new verifier.

All addresses are virtual addresses of the original node/115 ELF, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Complete byte-buffer connection

1. `0x4302cd0` creates two 40-byte tokens: tag0 contains the first twenty bytes; tag1 references a copied thirty-two-byte buffer. It passes count 2 to slot `0x64e0140`, bound to `0x169e350`.
2. Normalization `0x169c190 -> 0x169dcc0` preserves token order and produces two 32-byte descriptors of class0/count1. `0x169e650` reports 32 head bytes per descriptor; `0x169e6d0` reports zero tail bytes. The sum is 64.
3. The native allocator request at `0x169e3eb` is **2,048 bytes**, because the accounting value 64 is shifted left five. The resulting intermediate word-vector capacity is 64 words and live length starts at zero. This is distinct from the final 64-byte preimage; the report does not equate these sizes or speculate about the over-allocation.
4. `0x169e1d0` calls `0x169e5a0` for each head. Class0 forwards the token to `0x169df80`. Tag0 creates a word with twelve zero bytes followed by the twenty input bytes, writes its two 16-byte halves to slot 0, and publishes live length 1. Tag1 length32 computes one full final chunk, calls the imported `memcpy` for exactly 32 bytes, writes slot 1, and publishes live length 2. Both appends have spare capacity (lengths 0 and 1 are below 64), so the growth helpers are bypassed. The class0 second-pass table target skips tail writing.
5. `0x169e44a..0x169e48d` constructs the flatten descriptor: front/back fragment flags are zero, owned begin and current equal the word-buffer pointer, end is pointer plus `2*32`, and word capacity is 64.
6. `0x169bf30` forces both fragment lengths to zero and computes `end-current=64`. It allocates exactly 64 output bytes. The loop at `0x169c080..0x169c0a0` copies the two words in order using two 16-byte loads/stores per iteration, advancing source and destination by 32. It frees the old word buffer using its 64-word capacity and returns `{capacity:64, pointer, length:64}` at `0x169c117..0x169c11e`. The output buffer has its own allocation.

This proves the selected successful byte sequence, not a general ABI encoder, allocator identity, arbitrary-token correctness, allocation failure or unwind cleanup contract. Valid input storage and ordinary successful allocation, copying and deallocation are premises.

## Actual inner digest

At `0x4526f31`, the caller receives the byte descriptor from `0x4302cd0`. It initializes a zeroed sponge state with rate136 and suffix1, loads the returned pointer and live length at `0x4526fc1/0x4526fc6`, and invokes absorb slot `0x64e0148 -> 0x5cda910`. It requests 32 output bytes from finalize slot `0x64e0150 -> 0x5cdad40`.

For exactly 64 input bytes, the selected short-input absorber XORs two 32-byte chunks into the initially zero state, publishes cursor64, and does not permute during absorption. Finalization XORs suffix1 at byte64 and bit0x80 at byte135, calls the pinned permutation once, resets the cursor, and copies the first32 state bytes. The source uses little-endian lanes and the unchanged permutation through a local adapter crate. It implements this bounded single-block relation only.

The earlier twenty-byte-producing helper, the upstream thirty-two-byte computation, chain selector, later returned object, domain signing and full bridge message semantics remain outside scope. Synthetic inputs contain no private keys and no requests are sent anywhere.

## Validation

Run from the repository root with the audited offline Python environment (Capstone 5.0.7) and Rust 1.95.0:

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-bridge-preimage/Cargo.toml
cargo +1.95.0 test --release --offline --locked --manifest-path src/node115-bridge-preimage/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-bridge-preimage/Cargo.toml -- -D warnings
python research/work-items/RE-005-node115-bridge-preimage/verify.py
python research/work-items/RE-005-node115-bridge-preimage/compare-openssl.py
make doctor verify catalogue-check reproduce
```

Two Rust tests pass in debug and release, including 64 public synthetic preimage/digest fixtures independently generated and checked with local OpenSSL 4.1.0 `KECCAK-256`. The inputs cross eight twenty-byte patterns with eight thirty-two-byte patterns. The retained fixtures and OpenSSL comparison command make the reference check reproducible. Clippy and formatting pass. These comparisons validate the authored bounded source against the reference algorithm; they do not execute or emulate the captured target or establish general target equivalence.

The static verifier checks 21 windows (2,870 bytes / 730 instructions), 131 facts and 21 semantic corruption controls. `verification.json` and `openssl-comparison.json` retain results. Controls change count/length, flatten extents and fragment flags, field alignment/padding, copy length, vector stride, returned length, digest inputs/rate/suffix/size and helper bindings. They bypass the target digest guard for their synthetic overlays and must fail the fact checks. The original artifact remains unchanged. Full `make test` is excluded because its discovery includes captured-instruction emulation.

## Overlap and remaining work

Current main, current open PR titles/bodies and targeted all-state historical searches for the builder, digest caller, flattening scope and related bridge preimage work were checked; no competing contribution was identified. The existing static-framing and sponge packets are credited above. Historical metadata searches do not guarantee manual inspection of every historical diff.

Remaining work includes full request decoding/schema, upstream field semantics, nonce/admission/authorization, state mutation and persistence, general ABI/digest paths and runtime equivalence. No issue is closed.
