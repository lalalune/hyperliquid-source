# RE-005: Node #115 `z_forks/bincode-fork` CGU ThinLTO Compiled-Byte Matches (12 FDEs, 7,170 B)

Component: `serialization` (`z_forks/bincode-fork`).
Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`), SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Summary

Live-rebuilds `main.rs` (`#![forbid(unsafe_code)]`, 0 external deps) under
`rustc +1.95.0 --edition=2021 --crate-name bincode_cgu_thin -C opt-level=3 -C overflow-checks=yes -C lto=thin -C save-temps`
and verifies **12/12 brand-new, zero-overlap, 100.00% relocation-qualified**
FDE matches (`7,170 B`, `6,434/7,170 = 89.74%` raw-equal) inside the 19-FDE
`z_forks/bincode-fork` CGU (`0x1607c70..0x1609aaa`, `7,575 B`):

| FDE Range | Bytes | Raw-Equal | Symbol / Role |
|---|---:|---:|---|
| `0x1607c70..0x1607e03` | 403 | 379 | `core::fmt::num` Debug (`0x6403300`) |
| `0x1607e10..0x1607fb5` | 421 | 397 | `core::fmt::num` Debug (`0x6403160`/`0x64032c0`) |
| `0x1607fc0..0x1608165` | 421 | 397 | `<&u64 as Debug>::fmt` (`0x64031e0`) |
| `0x1608170..0x1608313` | 419 | 395 | `<&u32 as Debug>::fmt` (`0x64031c0`) |
| `0x1608340..0x1608666` | 806 | 737 | `<&[u8; 4] as Debug>::fmt` (`InvalidCharEncoding`) |
| `0x1608670..0x16087a0` | 304 | 277 | `<&u8 as Debug>::fmt` (`InvalidBooleanValue`) |
| `0x16087a0..0x16090ed` | 2,381 | 2,037 | `<&DecodeError as Debug>::fmt` (all 18 variants incl. fork `InvalidBytesLength`) |
| `0x1609100..0x1609301` | 513 | 453 | `<&AllowedEnumVariants as Debug>::fmt` (`0x6403260`) |
| `0x1609330..0x160948a` | 346 | 310 | `<&Option<u8> as Debug>::fmt` (`0x6403180`) |
| `0x1609490..0x1609635` | 421 | 397 | `<&i64 as Debug>::fmt` (`InvalidDuration::secs`) |
| `0x1609640..0x1609842` | 514 | 466 | `<&[u32] as Debug>::fmt` (`AllowedEnumVariants::Allowed`) |
| `0x1609850..0x160992d` | 221 | 189 | `<&Utf8Error as Debug>::fmt` (`0x6403280`) |

Combined with `RE-012-node115-stream-c-byte-matches` (2 CGU FDEs, `91 B`) and
`RE-005-node115-bincode-fork-gate-closure` (4 CGU FDEs, `105 B` + 4 business-logic
varint slow decoders, `939 B`), this achieves **18/19 FDEs = 7,366 / 7,575 B (97.24%)**
of the entire `z_forks/bincode-fork` CGU (100% of all non-jemalloc-`sdallocx` FDEs;
only `0x1609960` `drop_in_place::<std::io::Error>`, 209 B, calls jemalloc `sdallocx`),
plus **939 B** of pure business-logic `bincode::varint` slow decoders = **8,305 B** total
verified `z_forks/bincode-fork` compiled-byte identity.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-005-node115-bincode-fork-cgu-thinlto-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_bincode_fork_cgu_thinlto_115 -v
```
