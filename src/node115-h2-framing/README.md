# Node115 H2 framing value component

This standalone dependency-free analysis crate implements the established scalar
builder cap, actual H2 limit/continuation relation and one length-decoder step.
It is MIT, independently authored, and is not an integrated node or original ABI.
The native relation assumes valid stable byte-buffer storage and the helper
postconditions in `research/work-items/RE-012-h2-framing-115/CONTRACT.md`.

`decode` returns consumption and a frame interval without allocating, reading a
socket, following native pointers or executing captured instructions. It reports
native failure boundaries separately; these are not original error enum layouts.
Use the returned Data state with the unconsumed bytes and subsequent input.

```sh
cargo test --offline --manifest-path src/node115-h2-framing/Cargo.toml
python3 -B -O research/work-items/RE-012-h2-framing-115/native/qualify.py \
  --rustc /path/to/rust-1.94.1/bin/rustc \
  --rustc /path/to/rust-1.95.0/bin/rustc --out NEW_DIRECTORY
```

The qualifier compiles and executes this own Rust only. The frozen oracle and
recorded output hashes precede publication. It never starts the captured node.
