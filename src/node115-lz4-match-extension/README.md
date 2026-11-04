# node115 LZ4 forward match extension

Independent MIT `no_std` implementation of the complete logical helper at
ELF VA `0x477e7c0..0x477e941` in Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`extend(left, right, &mut cursor, right_cursor)` counts additional equal bytes
and advances only the left cursor. It stops before the left slice's last six
bytes and at the right slice's end, whichever comes first. It uses eight-byte
little-endian XOR plus trailing-zero counting, then a scalar remainder. The
inputs may alias. The result excludes the caller's initial four-byte match.

A safe adapter rejects left slices shorter than six bytes. The target's raw
length-minus-six wraps outside that domain; this is not presented as its native
error. Left cursor beyond `left.len()-6` and right cursor beyond `right.len()`
represent observed failure-helper boundaries, in that order, without cursor
mutation. Native panic objects, pointer provenance and ABI are not reproduced.

Evidence and pre-Rust frozen expectations:
`research/work-items/RE-012-lz4-match-extension-115/`.
This helper does not implement dictionary initialization, match selection,
backward extension, token/offset emission, or a complete compressor. Full-scope
gates and compiled-byte coverage remain unchanged.

```
cargo +1.95.0 build --offline --locked --manifest-path src/node115-lz4-match-extension/Cargo.toml
python3 -B research/work-items/RE-012-lz4-match-extension-115/qualify.py
```
