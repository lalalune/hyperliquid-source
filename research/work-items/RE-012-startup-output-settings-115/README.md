# RE-012 · Startup output settings in Rust

The [source-built reader](../../../src/node115-startup-output/src/lib.rs)
takes the presence and value lookups of an already parsed command. The
two run commands share constructor `0x564d390..0x564d6d8` in Linux x86-64 node
#115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The evidence base is `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`.
The new MIT Rust implementation covers the logical configuration used during startup.

The [constructor](../RE-012-node115-cli-output-config/CONTRACT.md) orders the
14 lookups and supplies three distinct style tags. An absent clearinghouse
value stays absent; a present value, including an empty one, is copied.
Style errors distinguish the two observed failure boundaries in a safe Rust
interface. The [poller conversion](../RE-008-output-flags-path-115/README.md)
and [origin analysis](../RE-008-output-flags-origin-115/README.md) establish the
selected layout used to associate seven flags with [writer names](../RE-008-output-flags-115/README.md).
The names describe enabled gates, regardless of subsequent file or allocation
success. The stream conflict is a separate setter condition. The reader
preserves both service flags; the selected setter never reads the serve-info byte.

From the repository root:

```sh
python3 -B research/work-items/RE-012-startup-output-settings-115/verify.py
cargo test --locked --offline --manifest-path src/node115-startup-output/Cargo.toml
```

The first command authenticates the image and re-derives the fixture using the
existing binary extractor. The Rust test compares the 12 flags in all 4,096
combinations and checks the three style tags, exact lookup order, missing or
empty values, ownership of caller bytes and invalid style text. Only the
independently built Rust runs. Parsing argv, native ABI, filesystem effects,
alternate poller branches and complete node startup remain outside this work.
