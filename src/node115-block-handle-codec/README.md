# Node #115 BlockHandle codec

This crate independently implements the target-bound BlockHandle byte format
from `research/work-items/RE-001-block-handle-codec-115/`. Evidence is bound to
Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The wire form is unsigned LEB128 `offset` followed by unsigned LEB128 `size`.
The decoder mirrors the target's non-canonical behavior: it accepts overlong
varints up to ten bytes, retains only bit zero from the tenth byte, and rejects
a continuation bit on that byte. It zeroes the output handle on failure,
commits the input cursor after each successfully decoded varint, and returns
corruption code 2 with `bad block handle`.

This crate models the byte codec and decode state only. It does not model C++
`std::string` allocation, max-size exceptions, the target ABI, or RocksDB call
sites. The packet's native Unicorn runs are independent evidence; these Rust
tests never execute the captured binary.

Run from the repository root:

```sh
cargo test --offline --manifest-path src/node115-block-handle-codec/Cargo.toml
cargo fmt --manifest-path src/node115-block-handle-codec/Cargo.toml -- --check
cargo clippy --offline --manifest-path src/node115-block-handle-codec/Cargo.toml -- -D warnings
python3 tests/test_block_handle_codec_115.py
```
