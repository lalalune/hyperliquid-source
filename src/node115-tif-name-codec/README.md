# Node #115 Tif name codec

This dependency-free `no_std` Rust crate ports the target-grounded order
time-in-force name codec for `Alo`, `Ioc`, `Gtc`, `FrontendMarket`, and
`LiquidationMarket`. It maps the five exact, case-sensitive names to tags
0 through 4, writes each name as a MessagePack fixstr, and preserves the
visitor's lossy UTF-8 behavior for unknown byte input.

The port is limited to enum name/tag and emitted wire bytes. It does not model
the serializer's internal Vec reserve/growth call sequence, serde error
construction, caller structures, or book transitions. The source type
interpretation of “Tif” is inferential; the names, tag order, visitor results,
and serializer bytes are target observations. No component gate or
byte-equivalence claim is made.

## Target evidence

The behavior is bound to Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The
static packet
[`RE-006-tif-codec-115`](../../research/work-items/RE-006-tif-codec-115/README.md)
interprets three serializer bodies and ten visitor bodies from their original
bytes. Its retained fixtures include 1,260 serializer rows and 2,352 inputs
compared across ten visitors (23,520 visitor cases). The Rust tests consume
those fixtures; the captured executable is never run.

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-tif-name-codec/Cargo.toml
python3 -m unittest tests.test_re006_tif_codec_115
```

The Rust tests compare emitted fixstr bytes, tags, all visitor result words,
error statuses, and lossy unknown byte values against the retained
target-interpreter vectors. The focused Python test regenerates/checks the
static evidence using the authenticated target digest. It interprets selected
instruction bytes and does not execute the captured node.
