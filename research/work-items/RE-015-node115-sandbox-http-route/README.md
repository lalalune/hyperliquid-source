# Why the reconstructed workspace reported localhost for Sandbox

Two HTTP URL consumers in node #115 map Local, Sandbox, Testnet and Mainnet to four different selector values. The previous workspace health check grouped Sandbox with Local and returned localhost for both. The two callers and the data formatter establish that Sandbox needs its configured IPv4 address. The offline workspace health report now exposes a missing address, and the pure URL resolver accepts one explicitly.

| Chain byte | Suffix selector | Node #115 destination | Selected HTTP base |
| ---: | ---: | --- | --- |
| 0, Local | 6 | 0x154b017 | http://localhost:3001/ |
| 1, Sandbox | 4 | 0x154b053 | http://{WebSandbox IPv4}:3001/ |
| 2, Testnet | 3 | 0x154b265 | https://api.hyperliquid-testnet.xyz/ |
| 3, Mainnet | 2 | 0x154afd3 | https://api.hyperliquid.xyz/ |

At 0x2ae8057 and 0x2cb3857 the callers reach the same helper after shifting the packed selector word 0x0002000300040006 by 16 times the chain byte. Each caller then loads the compact formatting descriptor for the four literal bytes “http”, followed by the returned suffix. The helper's six signed jump entries start at 0x466d10.

On the Sandbox arm, 0x154b089 selects the ten-byte lookup key WebSandbox. The matching entry supplies a four-byte value at 0x154b234. The formatter slot 0x64e1068 has a relative relocation to 0x16885f0, the registry's Rust 1.95.0 core::net::Ipv4Addr Display implementation. Its body digest is verified. The format descriptor at 0x4366c1 supplies the literal prefix “://” and trailing “:3001/”. The separate selector-6 arm builds its 18-byte localhost suffix without this lookup. The helper has other entry modes outside these two consumers.

[PR #86](https://github.com/lalalune/hyperliquid-source/pull/86) documented the historical node #94 suffix dispatch. [The prior node #115 location packet](../RE-001-node115-location-154b36a/README.md) identifies the source file and the missing-key branch. This packet binds the two current caller selectors to all four chain values, qualifies the configured IPv4 formatter and fixes the reconstructed workspace report. It does not access process configuration, make network requests or establish the configured value on any deployment.

## Replay

From the repository root with the authenticated Linux x86-64 node #115 materialized, run the following.

```sh
python3 -B research/work-items/RE-015-node115-sandbox-http-route/verify.py
cargo test --offline --locked --manifest-path src/hl-node/Cargo.toml --test cli_and_workspace
```

Target SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The regression originally observed exactly the same localhost value for both chains. The fixed controls cover Local without configuration, Sandbox with and without a documentation-range IPv4 address, and both static public chains. [Recorded target measurements](result.json) reproduce without executing the captured node.
