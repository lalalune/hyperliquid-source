# RE-012 — Stream C (`serialization`, `transport`, `node-runtime`) First-Party Compiled-Byte FDE Matches

- **Target**: Linux x86-64 node `#115` (`artifacts/node/115/hl-node`), SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- **Toolchain**: `rustc 1.95.0 (59807616e 2026-04-14)` with `--edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes --emit=obj` (`#![forbid(unsafe_code)]`, 0 external dependencies).
- **Scope**: **34 authenticated, non-overlapping, 100.00% relocation-qualified first-party `.text` FDE matches (1,182 B total)** across all three Stream C components (all currently at 0 B in `src/node115-first-party-byte-census`):
  - **`serialization` (`z_forks/bincode-fork`)**: 2 windows / **91 B** (`0x1609a40` 44 B `IntegerType::fmt`, `0x1609930` 47 B `&IntegerType::fmt`, verified against `.data.rel.ro 0x6403308` -> `.rodata 0x46aa30` `"U8"..="Reserved"`).
  - **`transport` (`net_utils`)**: 3 windows / **75 B** (`0x47831a0` 25 B & `0x5942610` 25 B `net_utils::rate_limiter::AlertConfig` `Visitor::expecting`, `0x4783180` 25 B `AlertConfig` field `Visitor::expecting`).
  - **`node-runtime` (`node`)**: 29 windows / **1,016 B** (`0x2c7c740` 156 B & `0x5a2e380` 156 B `&GossipStatus::fmt`, `0x5a2e340` 54 B `&VisorKind::fmt`, plus 26 verified 25 B `Visitor::expecting`/`Display::fmt` FDEs for `GossipConfigInner`, `FirewallEntry`, `VisorTimeLock`, `NodeIpParseError`, `NodeIp`, `Hardfork`, `NodeGossipPriorityConfig`, `VisorMetadata`, `NodeMetadata`, `HotfixArgs`, `HotfixMetadata`, `PublisherBinaryMetadata`, `ErrDurGuard`).

## Verification

- `PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-012-node115-stream-c-byte-matches/verify.py --self-test`
- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_stream_c_byte_matches_115 -v`
- `(cd research/work-items/RE-012-node115-stream-c-byte-matches && sha256sum -c MANIFEST.sha256)`
