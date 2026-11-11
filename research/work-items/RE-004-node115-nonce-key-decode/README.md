# Nonce tuple first field: fixed-width decoded-string conversion

This packet advances issue #3914 by closing the selected fixed-width visitor that the earlier nonce-provider work left opaque. The real tuple caller initializes twenty output bytes to zero and passes a fixed-width descriptor to a JSON string reader and hex conversion visitor. The new Rust crate reconstructs conversion of the **already decoded string bytes**, including the native whitespace and partial-output behavior. It does not identify this field as an address or prove admission, authorization or persistence. Issue #3914 remains open.

## What the native path establishes

The source is the original pinned node/115 ELF, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. All addresses are virtual addresses.

The previous nonce text-provider evidence already maps the bracketed provider, vector ordering, and outer two-element tuple at `0x1ddf3b0`. This packet's added scope starts at that tuple's previously opaque first-field decoder:

- `0x1ddf4dc..0x1ddf50d` zeros 16 bytes and a final dword, constructs `{kind:0, output_pointer, width:20}`, and calls `0x1e3e180`. On success, the tuple later reloads the twenty bytes. The decoder's written-count return does not replace or resize that fixed field.
- `0x1e3e180` skips JSON whitespace, requires an opening quote, and calls slot `0x64e08f8`, resolving to `0x5c56b60`. It forwards the resulting string pointer and byte length to `0x26fa2a0`. JSON escape decoding, UTF-8 and string error construction remain that reader's contract, outside the reconstructed source.
- `0x26fa2a0` strips an optional **lowercase** `0x` prefix. Under caller kind 0, it requires the remaining byte length to equal `2*20`, before decoding any digits. Uppercase `0X` is not a recognized prefix. The range-width visitor branch is excluded.
- It calls slot `0x64e0bd0`, resolving to `0x2eabce0`, with the adjusted pointer, forty-byte length, output pointer, capacity twenty, and a prefix-present flag.
- `0x2eabce0` accepts `0..9`, `A..F`, `a..f`, and skips exactly TAB, LF, CR and SPACE (bit mask `0x100002600`). The raw forty-byte length includes those whitespace bytes. Its phase starts from `length & 1` (zero here); it emits one byte per two digits. A final unmatched nibble is not flushed. Both ordinary end-of-input and trailing-whitespace paths return success tag 2 with the written count, without enforcing twenty emitted bytes.
- The visitor accepts that success without another output-width check. Therefore skipped whitespace can leave a zero-filled suffix, and a lone final nibble can be discarded. Invalid bytes return their value and decoded-string byte index, adjusted by two when the prefix was stripped. The Rust error enum represents these categories; native allocated error text/objects are not reproduced.

For example, a decoded string of `"123"` followed by 37 spaces has the required forty-byte width. It produces `12` followed by nineteen zero bytes: the pending `3` nibble is dropped. Forty spaces produce twenty zero bytes. These are selected decoder facts, not a claim that a live request carrying such a field is accepted by higher-level validation.

## Source and validation

`src/node115-nonce-key-decode` is dependency-free, `no_std`, and forbids unsafe code. `decode_key(&[u8])` returns a fixed `[u8;20]` or a length/invalid-byte error. The input is a decoded string, not an entire JSON document. The output index is bounded because forty input bytes can produce at most twenty pairs.

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-nonce-key-decode/Cargo.toml
cargo +1.95.0 test --release --offline --locked --manifest-path src/node115-nonce-key-decode/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-nonce-key-decode/Cargo.toml -- -D warnings
python research/work-items/RE-004-node115-nonce-key-decode/verify.py
make doctor verify catalogue-check reproduce
```

Four Rust tests pass in debug and release. They cover mixed-case digits and prefix handling, whitespace and unmatched-nibble behavior, exact-width/error precedence, and all 256 byte values at four positions with invalid-byte offsets (1,024 byte-position cases). Clippy and formatting checks pass. These are tests of independently authored source against explicit static-derived expectations; no target differential execution or external library comparison is claimed.

The static verifier checks five windows (1,081 bytes / 292 instructions), 90 facts and 16 semantic corruption controls. It authenticates the target and FDE boundaries, retains instruction rows, and rejects mutations to initialization, width, prefix, whitespace mask, digit ranges, nibble shift, output write, return tag and helper relocation. Mutation checks bypass the global digest guard to exercise the recorded facts; the original target remains unchanged. `verification.json` retains the result. No captured code is executed or emulated. Full `make test` is excluded because discovery includes captured-instruction emulation.

## Overlap and limits

Current main, open PR titles/bodies, and targeted all-state searches for `0x1e3e180`, `0x26fa2a0`, `0x2eabce0`, and the fixed-width nonce-field semantics found no competing implementation. The previous nonce provider's `PROOF.md` explicitly leaves this first decoder opaque; its outer tuple/vector findings are reused rather than claimed as new. Historical title/body searches do not amount to manual inspection of every historical diff.

Remaining work includes JSON string parsing, full record decoding, field identity, actual nonce admission and persistence, native error object formatting, and whole-component equivalence. No issue is closed and no component gate is raised.
