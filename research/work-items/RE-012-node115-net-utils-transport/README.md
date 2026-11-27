# RE-012: Node #115 `net_utils` transport, LZ4 framing, gossip & HTTP/2 integration

Component: `transport`. Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`),
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Binary Observations

1. **All 12 observed `net_utils` source paths anchored to `.rodata`, `.data.rel.ro` `core::panic::Location`, and `.text` FDEs**:
   - `net_utils/src/async_sleep_retry.rs` (`0x436a80`): L30:44 / L32:38 / L41:62 (`0x644aed0`, `0x644aee8`, `0x644af00`; FDE `0x2a64130..0x2a64bd7`), logs `"async_sleep_retry retried "` (`0x44c680`) and `"async_sleep_retry retries exhausted: "` (`0x444d45`).
   - `net_utils/src/channel.rs` (`0x435a64`): L97:47 / L117:30 (`0x644f5f0`, `0x644f5d8`; FDE `0x2ced6b0..0x2ced915`).
   - `net_utils/src/ip_semaphore.rs` (`0x432e0f`): L28:35 (`0x6496560`; FDE `0x47710e0..0x477165a`), L37:51 (`0x6496548`; FDE `0x4770f40..0x47710d9`). Global permit acquired first (`lock cmpxchgq` -2 at `0x4770f87`), refunded on per-IP failure (`0x4771053`); metric suffix `"_ip_semaphore"` (`0x43be71`).
   - `net_utils/src/rate_limiter.rs` (`0x439f4a`): L131:20 (`0x64b6f68`; FDEs `0x59db700..0x59db98d`, `0x59db990..0x59dbc1d`), clears 4 per-IP HashMaps on window reset; `.rodata` strings `"rate_limiter_bytes_per_sec"` (`0x43d808`) and `"struct AlertConfig"` / `"bucket_limit_mult_threshold"` (`0x7e1c28`).
   - `net_utils/src/rw_lock.rs` (`0x432e59`): L110:14 (`0x64ab898`; FDE `0x5649680..0x5649deb`), L125:37 (`0x649ee38`), L130:37 (`0x649ee50`); prefixes `"profiled_rw_lock/"` (`0x432e2e`) and `"blocked_writer/profiled_rw_lock/"` (`0x4491ed`).
   - `net_utils/src/tcp/lz4_stats.rs` (`0x436ce6`): L68:18 (`0x64976d0`; FDE `0x47855c0..0x4785a0a`), L80:42 (`0x64976b8`; FDE `0x4784e90..0x47855b4`); reporting window `f64 = 300.0` (`0x458f40`), prefix `"tcp_lz4/"` (`0x44f829`), direction labels `"in"`/`"out"` (`0x7e1c9c`).
   - `net_utils/src/tcp/traffic_recorder.rs` (`0x44cbc4`): L64:47 (`0x6497448`; FDE `0x4781880..0x4781f09`); reporting window `f64 = 30.0` (`0x458cd8`), counter `"tcp_bytes"` (`0x93c5a2`).
   - `net_utils/src/tcp/read.rs` (`0x43ada2`): L19:110 / L24:77 / L35:13 / L51:47 (`0x644aff0`, `0x644afa8`, `0x644afc0`, `0x644afd8`; FDE `0x2b79e30..0x2b7a0a3`); error prefixes `"TcpRead::bincode err: "` (`0x444d6e`) and `"decompress_lz4 failure: "` (`0x44ea13`).
   - `net_utils/src/tcp/write.rs` (`0x44819b`): L11:17 / L15:120 / L25:98 / L34:17 / L54:13 (`0x644b008`, `0x644b050`, `0x64bb1a0`, `0x644b020`, `0x644b038`; FDE `0x2b7a140..0x2b7a28e`), write timeout constant `0x404e000000000000` (`f64 = 60.0` s) at `0x2b7a193`.
   - `net_utils/src/tcp/tcp_stream.rs` (`0x434a64`): L33:60 / L45:80 / L50:73 / L60:82 (`0x644af60`, `0x644af18`, `0x644af30`, `0x644af48`; FDE `0x5ab3a50..0x5ab3b81`).
   - `net_utils/src/tcp/tcp_client.rs` (`0x441647`): L25:70 / L41:21 / L45:84 / L50:115 / L55:13 / L73:20 / L83:20 (`0x64bb038`, `0x64bafc0`, `0x64bb050`, `0x64bafd8`, `0x64baff0`, `0x64bb008`, `0x64bb020`; FDEs `0x5ab2680..0x5ab2e59`, `0x5ab2e60..0x5ab3a4d`); prefixes `"TcpClient connect "` (`0x431e1e`), `"TcpClient write "` (`0x441668`), `"TcpClient read "` (`0x443412`), `"TcpClient::read_bincode_response decode err: "` (`0x43b14b`), `"TcpClient not connected"` (`0x93c582`), `"ip not v4"` (`0x93c599`).
   - `net_utils/src/tcp/tcp_listener.rs` (`0x448179`): L11:57 / L17:67 (`0x644af78`, `0x644af90`; FDE `0x2afae20..0x2afbc22`).

2. **Observed TCP Frame & LZ4 Protocol Parameters**:
   - 5-byte frame header `[u32 BE payload_len, u8 compressed_flag]`; `flag == 1` triggers size-prefixed LZ4 decompression, any other flag is raw.
   - Outbound compression threshold: `input_len < 1025` or ports `3998`/`3999` send raw (`flag = 0`); otherwise LZ4 size-prepended (`SmallTable` 8 KiB for `< 65535`, `LargeTable` 16 KiB for `>= 65535`).
   - Chunked receive size `4_000_000` bytes; listener prefix limit `11_000_000` bytes.

## Implementation & Limits

Independently authored MIT crate in `src/net-utils/` integrating `bincode-fork` and 19 verified node #115 transport, LZ4, greeting, gossip, and HTTP/2 framing micro-crates, with zero external crates.io dependencies.
Async Tokio runtime internals and compiled binary identity are out of scope for this packet.

## Reproduce

```sh
python3 -m unittest tests/test_net_utils_transport_115.py
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/net-runtime \
  cargo test --manifest-path src/net-utils/Cargo.toml
```
