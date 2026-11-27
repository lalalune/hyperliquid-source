# RE-012: Node #115 `transport` (`net_utils/src/*.rs`) Complete 12-File / 68-Location / 62-FDE Full-Scope Closure

- **Component ID**: `transport` (`net_utils` crate: all 12 observed source files under `net_utils/src/`).
- **Workspace crate**: `src/net-utils` (`#![forbid(unsafe_code)]`, pure `std` + verified Stream C node #115 micro-crates, zero external crates.io dependencies).
- **Target release**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, `105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Static verification only**: Captured binary is never executed.

## Complete `net_utils/src/*.rs` Inventory (12/12 Files, 68/68 Locations, 62/62 FDEs = 258,511 B)

Every `.data.rel.ro` `core::panic::Location` struct whose path begins with `net_utils/src/` (all 68/68, 0 unreferenced) and every `.text` FDE referencing any of those 68 `Location`s (all 62/62) is authenticated in `records.json`:

1. **`net_utils/src/async_sleep_retry.rs` (9 Locations, lines `30, 32, 41`)** -> `src/net-utils/src/primitives.rs`:
   - Exponential-backoff sleep retry loop (`RetryPolicy`, `RetryExhausted`, `sleep_retry`) preserving `.rodata 0x444d46` `"async_sleep_retry retries exhausted: "`.
2. **`net_utils/src/channel.rs` (6 Locations, lines `97, 117`)** -> `src/net-utils/src/primitives.rs`:
   - Bounded multi-producer/multi-consumer metered channel (`BoundedChannel`, `ChannelError`) with queue-depth & dropped-full tracking (`0x2ced6b0`, `0x5ab6df0`, 14 FDEs total).
3. **`net_utils/src/ip_semaphore.rs` (2 Locations, lines `28, 37`; 2 FDEs = 1,811 B)** -> `src/net-utils/src/ip_semaphore.rs`:
   - Two-level global + per-IP RAII permit semaphore (`0x4770f40..0x47710d9`, `0x47710e0..0x477165a`), periodic `60.0`s telemetry/cleanup interval (`0x477116a: 0x404e000000000000`), `0.8` (80%) utilization warn threshold (`0x4771300: 0x3fe999999999999a`), and `.rodata 0x432e0f` path anchor.
4. **`net_utils/src/rate_limiter.rs` (1 Location, line `131`; 2 FDEs = 1,306 B)** -> `src/net-utils/src/rate_limiter.rs`:
   - Sliding-window per-IP + global byte/request rate limiter with periodic map-clearing window reset (`0x59db700..0x59db98d`, `0x59db990..0x59dbc1d`) and `AlertConfig` (`0x7e13cd`, `bucket_limit_mult_threshold`).
5. **`net_utils/src/rw_lock.rs` (3 Locations, lines `110, 125, 130`; 8 FDEs = 7,359 B)** -> `src/net-utils/src/primitives.rs`:
   - `ProfiledRwLock` (`"profiled_rw_lock/"` at `.rodata 0x432e2e`) with `0.05`s (`50` ms, `0x56496fb -> 0x459038`) slow-write threshold and `0.35`s (`350` ms, `0x5649789 -> 0x458f50`) critical-write threshold (`0x5649680..0x5649deb`, `0x4e44fd0..0x4e47f8c`).
6. **`net_utils/src/tcp/lz4_stats.rs` (2 Locations, lines `68, 80`; 2 FDEs = 2,926 B)** -> `src/net-utils/src/tcp.rs`:
   - Directional (`"in"` `0x7e1c9c`, `"out"` `0x7e1c9e`) LZ4 compression ratio telemetry (`0x4784e90..0x47855b4`, `0x47855c0..0x4785a0a`) with `300.0`s reporting window (`0x478540b -> 0x458f40`) and `0.5` ratio warn threshold (`0x47857c0: 0x3fe0000000000000`).
7. **`net_utils/src/tcp/traffic_recorder.rs` (1 Location, line `64`; 1 FDE = 1,673 B)** -> `src/net-utils/src/tcp.rs`:
   - Per-IP + aggregate TCP byte recorder (`0x4781880..0x4781f09`, `"tcp_bytes"` `0x93c5a2`) with `30.0`s reporting window (`0x4781d3a -> 0x458cd8`).
8. **`net_utils/src/tcp/read.rs` (12 Locations, lines `19, 24, 35, 51`)** -> `src/net-utils/src/tcp.rs`:
   - 5-byte framed TCP reader (`[u32 BE len, u8 compressed]`), `CHUNK_BYTES = 4_000_000` chunked reads (`node115-tcp-frame-plan`), over-limit rejection (`"tcp read bytes over limit"` `0x606ed5`), size-prepended LZ4 decompression (`node115-lz4-decode`), and `bincode-fork` decoding (`"TcpRead::bincode err: "`).
9. **`net_utils/src/tcp/write.rs` (9 Locations, lines `11, 15, 25, 34, 54`)** -> `src/net-utils/src/tcp.rs`:
   - 5-byte framed TCP writer with `60.0`s write timeout (`0x2b7a193: 0x404e000000000000`), port-aware LZ4 compression policy (`node115-tcp-compression-plan`: `< 1025` B or port `3998`/`3999` uncompressed), and `bincode-fork` encoding (`"TcpWrite::bincode err: "`).
10. **`net_utils/src/tcp/tcp_stream.rs` (10 Locations, lines `33, 45, 50, 60`)** -> `src/net-utils/src/tcp.rs`:
    - Framed TCP stream lifecycle (`FramedTcpStream`, `early eof` at `0x94d48e`, `TCP_NODELAY`, `60.0`s write timeout, LZ4 stats & traffic recorder hooks).
11. **`net_utils/src/tcp/tcp_client.rs` (7 Locations, lines `25, 41, 45, 50, 55, 73, 83`; 3 FDEs = 14,465 B)** -> `src/net-utils/src/tcp.rs`:
    - Framed TCP client (`TcpClient`, `0x5ab2680..0x5ab3a4d`, `0x59f73d0..0x59f988b`) enforcing IPv4-only (`"ip not v4"` `0x93c599`), `"TcpClient not connected"` (`0x93c582`), and `60.0`s write timeout (`0x5ab3556: 0x404e000000000000`).
12. **`net_utils/src/tcp/tcp_listener.rs` (6 Locations, lines `11, 17`; 5 FDEs)** -> `src/net-utils/src/tcp.rs`:
    - Framed TCP listener (`TcpListener`, `0x2afae20..0x2afbc22`) enforcing `LISTENER_LIMIT` (`node115-listener-prefix`), IPv4 check (`0x606ec3`), and `1.0`s accept retry sleep (`0x2afb0d4: 0x3ff0000000000000`).

Additionally, `src/net-utils` integrates the verified node #115 stream & wire protocols (`gossip.rs`: `GossipRpcRequest`, `GossipRpcResponse`, 7-variant `ClientBlocksError`, `GossipStatus`, `PeerEntry`; `stream_protocols.rs`: `AbciStreamGreeting`, `EvmKvsMsg`, `GreetingFixedPart`; `lz4.rs`: `SmallTable`/`LargeTable` compressor & decompressor; `framing::*`: 12 verified low-level framing/HTTP/2/TCP micro-crates).

## Compiled-Byte Identity Accounting (`transport`)

- `RE-012-node115-stream-c-byte-matches`: includes verified `net_utils` / transport windows (`0x4783180`, `0x47831a0`, `0x5942610`, etc.) and companion Stream C byte-match micro-crates (`node115-tcp-*`, `node115-lz4-*`, `node115-h2-framing`, `node115-frame-stream`, `node115-greeting-encoder`, etc.).
- `identity` gate remains strictly `false` until full-crate `net_utils` FDE compiled-byte identity is proved.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-012-node115-transport-net-utils-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_transport_net_utils_closure_115 -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo +1.95.0 test --offline --locked --manifest-path src/net-utils/Cargo.toml
```
