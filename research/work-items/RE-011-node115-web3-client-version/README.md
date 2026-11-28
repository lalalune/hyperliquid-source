# web3_clientVersion reports the selected chain

The integrated offline client-version handler returned the same package-like
identifier on every chain. The earlier EVM-RPC closure lists the registered
method name at 0x6025da. This replay follows that registration to the response
formatter and recovers each possible value.

## Callback and format operands

Input is the signed Linux x86-64 node 115 ELF, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Coordinates are ELF VAs. The registration at 0x2e37b17 builds the callback
context with the chain byte at offset 0x10. At 0x2e37b1c it selects the 18-byte
method name, then calls registration wrapper 0x2cff5c0. Both callback slots in
descriptor 0x64506f8 relocate to 0x2d01520. This distinguishes it from the
adjacent net_version registration, which supplies a different descriptor.

The callback advances to the captured chain byte and pairs it with the format
function in the relative slot at 0x64e0f30. It gives the formatting helper the
length-prefixed literal at 0x4378e9 plus one argument. The argument formatter
0x1778c60 indexes the four signed displacements at 0x4820f4. Each destination
loads a string address with its explicit length. The integrated handler reuses
the existing ChainDisplay implementation of that formatter. The four recovered
values, including spaces and capitalization, are in [result.json](result.json).

## Reproduce

From the root, using Python 3 and Rust 1.95.0:

```sh
python3 research/work-items/RE-011-node115-web3-client-version/replay.py
cargo test --locked --offline --manifest-path src/hl-node/Cargo.toml
```

At integration base 2da45cb0a761cff6b478e40421699857d87a94df the real loopback
test on Testnet received `hl-node/0.1.0-node115`. With the recovered formatter
it receives `hyperliquid evm Testnet`. The structural replay separately checks
all four jump targets and both relocations. A package version, a lower-case
chain name, or the net_version callback cannot satisfy those checks.

This establishes the ordinary client version response for this specific
binary and the reconstructed HTTP handler. It does not establish the adjacent
network ID configuration, full native transport, or crate codegen identity.
Native instructions were inspected statically. Existing inputs retain their
original rights.
