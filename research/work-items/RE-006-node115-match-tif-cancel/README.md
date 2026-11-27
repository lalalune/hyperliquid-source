# RE-006: node #115 orderbook crossing predicate, TIF dispatch (`0x936ecc`), self-trade/reduce-only match step (`0x5911dd0`), and OID cancel lookup (`0x23ce3e0`)

- Component ID: `orderbook` (`RE-006`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: observation for all ELF FDE extents, `.rodata` jump table `0x936ecc`, instruction encodings, constants, and GOT slots; inference for domain names (`Alo`/`Ioc`/`Gtc`/`FrontendMarket`/`LiquidationMarket`, `BadAloPx`, `IocCancel`, `SelfTrade`, `ReduceOnlyCancel`, `InsufficientMarginCancel`). No full-component acceptance gate is claimed by this packet alone.

## Evidence (node #115 static observations)

| VA / Range | Source diagnostic anchor | Observed #115 semantics |
| --- | --- | --- |
| `0x5901dd0` (`0x5902560..0x590265f`) & `.rodata` `0x936ecc` | `l1/src/book/book/impl_insert_order.rs:197,593,597` | **Crossing predicate** (`0x5902560..0x5902581`): `best_px = abs(best_key)`; `would_cross = (best_px == limit_px) \|\| ((best_px < limit_px) ^ side_byte)` (`Bid=0`: `best_ask <= limit_px`; `Ask=1`: `best_bid >= limit_px`). **TIF jump table** at `0x936ecc`: `0` (`Alo` -> `0x59025c6`, rejects crossing with `0x8000000000000006` + BBO), `1`/`3`/`4` (`Ioc`/`FrontendMarket`/`LiquidationMarket` -> `0x59025b0`, sets `is_ioc=1`, rejects non-crossing with `0x8000000000000008`), `2` (`Gtc` -> `0x590261a`, sets `is_ioc=0`). Upper cap check at `0x590264b`: `0x38d7ea4c68000` (`10^15`). |
| `0x5911dd0` (2,416B FDE, twin `0x5912740`) | `l1/src/book/book/impl_insert_order.rs:744` | **Taker-vs-resting match step**: splits `perp_id / 10_000` (reciprocal `0x346dc5d63886594b >> 11`), indexes clearinghouse (`+0x7c8/+0x7d0`, stride `0x510`). If `taker_rem == 0` returns status `3`. **Self-trade #1** (`0x5911e73`): 20-byte SIMD compare (`taker+0x60 == resting+0xf8`) -> status `2`. **Self-trade #2** (`0x5911eb8`): both `taker` and `resting` match 8-address predicate `0x421a520` (GOT slot `0x64e5ae8`) -> status `2`. **Resting reduce-only** (`0x5911f30`, byte `+0xc0`): queries resting signed position `szi` (`*0x64e4e80`); rejects with status `1` if `szi == 0 \|\| ((szi <= 0) ^ taker_side)`; else clamps `avail_resting = min(resting.sz, abs(szi))` and marks status `1` when `avail_resting < taker_rem && abs(szi) < resting.sz`. Clamps `trade_sz = min(avail_resting, taker_rem)` and enforces maker (`0x59120c8`) then taker (`0x59121aa`) `max_trade_sz` (`*0x64e5b20`), setting status `0` when maker margin clamps `trade_sz`. |
| `0x23ce3e0` (8,736B FDE, twin `0x23d0600`) | `l1/src/book/book_orders.rs:137,145`, `book/level.rs:32`, `qtys/impl_sz.rs:9` | **Cancel order lookup & owner gate**: fast-path `len == 1` compares `entry[0].oid == oid`; multi-entry hashes OID via `oid.wrapping_mul(0xf1357aea2e62a9c5).rotate_left(20)` (`0x23ce47a`), probes `0x26f5c10`, bounds-checks slab index `< book+0x90`, verifies slot (`stride 0x110`) not vacant (`tag != 2`), and runs 20-byte SIMD owner check (`slot+0xf8 == user`). |
| `0x50bcc80` (1,472B FDE, twin `0x50bd240`) | `l1/src/book/book/mod.rs:1148,1149` | **Opposite-side book-half traversal**: flips `side` via `xor $1, %dl`, indexes `book + 0xa8 + (side << 5)`, distinguishes B-tree (`0x8000000000000000` niche via `neg; jno`) vs sorted ring (`stride 0x80`). |

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 -m unittest tests.test_orderbook_match_tif_cancel_115
(cd research/work-items/RE-006-node115-match-tif-cancel && sha256sum -c MANIFEST.sha256)
```
