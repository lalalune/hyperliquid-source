# Read the configured network identity from both EVM RPC methods

The reconstructed HTTP server reported Testnet for Local and Sandbox. A query
with no chain mutations reproduces it in a fresh local workspace. Each
configuration now exposes its own network ID through the two registered read
methods. The existing transports use decimal for net_version and a hexadecimal
quantity for eth_chainId.

## Target and comparison

The pinned Linux x86-64 node 115 ELF has SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses below are ELF VAs. The earlier RE-011 evm-rpc closure identified
the two registration names. This packet follows their separate wrappers and
tests whether they read one common network setting.

| Field | net_version | eth_chainId |
| --- | --- | --- |
| Name loaded | 0x2e377fe | 0x2a05fe1 |
| Registration wrapper | 0x2cff400 | 0x2cff240 |
| Callback | 0x2cffb40 | 0x2d01390 |
| Chain accessor call | 0x2cffb72 | 0x2d013bf |
| Numeric field read | 0x2cffb7b | 0x2d013c8 |

The two distinct callback descriptors both lead to a lookup through relocation
0x64e2200. Each dereferences the returned chain configuration and reads +0x388.
The decimal callback formats this value via 0x167fea0.

Inside accessor 0x46f3eb0, the four-entry jump table at 0x7d92c4 selects the
four lazy configuration cells. Their relative initializer pointers supply
7, 8, 9 and 10 to the common builder at 0x4345010. At 0x434503b that builder
adds 989. The following named-chain lookup returns the original number or zero;
the caller keeps the original when it sees zero. The tagged chain field is stored
at stack offsets 0x3f0 and 0x3f8. Relative to the builder input at 0x80,
this is the 16-byte field at offsets 0x370 and 0x378. Fork configuration is
appended at 0x380. Finalization saves the tagged pair at 0x5bcd146 and
writes it back at 0x5bcd763. The reference-counted allocation includes a 16-byte
prefix, placing the numeric half at 0x388 as observed in both callbacks.

The static replay checks the names, both callback slots, both accessors and
payload offsets, all four cells and thunk immediates, common constructor bias
and the field copies. The four-case socket test on the independently written
reconstruction verifies eight responses. The public Testnet and Mainnet cases
control the two corrected internal profiles.

## Reproduce

From the repository root, using Python 3 and Rust 1.95.0:

```sh
python3 research/work-items/RE-011-node115-rpc-network-ids/replay.py
cargo test --offline --locked --manifest-path src/hl-node/Cargo.toml
```

Before the change, the Local net_version test on integration base
2da45cb0a761cff6b478e40421699857d87a94df received 998. It now receives
996. Sandbox returns 997, Testnet 998 and Mainnet 999. These values describe
the four configurations of node 115. The evidence does not assert broader
chain-spec parity or an allocation in a public chain registry. No signed
transaction, live chain, or captured executable is used.
