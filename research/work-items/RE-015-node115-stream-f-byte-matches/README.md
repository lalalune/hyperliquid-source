# RE-015: Node #115 Stream F First-Party Compiled-Byte FDE Matches (138 Windows / 6,060 B)

- **Component Scope**: Stream F (`info-api`, `evm-rpc`, `evm`, `bridge`, `constants`)
- **Target Artifact**: `artifacts/node/115/hl-node` (Linux x86-64 ELF, 105,896,032 bytes)
- **Target SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Toolchain**: `rustc 1.95.0 (59807616e 2026-04-14)` (`--edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes`)
- **Source**: `lib.rs` (`#![forbid(unsafe_code)]`, 0 external crates.io dependencies)
- **Claim Status**: Every matched FDE extent, SHA-256 digest, relocation list, RIP-relative `.rodata` string target, and `tools/byte_progress.py::compare` result is directly verified against the authenticated node #115 ELF (never executed). Zero overlap with `research/byte-windows.json`, `RE-009-node115-storage-abci-byte-matches`, or `RE-007-node115-stream-e2-byte-matches`. No acceptance gate is modified by this packet.

## Verified Coverage Summary

| Component | Matched Windows | Total `.text` Bytes | Key Highlight |
|---|---:|---:|---|
| `info-api` | 42 | 3,579 B | `NodeInfoRequest` 55-variant JSON `visit_str` (`0x2744200`, 2,554 B, 2,383/2,554 raw-equal, 0 non-relocation diffs) + 41 `Visitor::expecting` FDEs (brings `info-api` off 0 B) |
| `evm-rpc` | 7 | 175 B | `JsonRpcResult::{Error,Success}`, `JsonRpcError`, `JsonRpcResponse`, `ParamsObject`, `EvmRpcConfig` (brings `evm-rpc` off 0 B) |
| `evm` | 55 | 1,375 B | `ReceiptWire`, `EvmBlockWire`, `TxEip7702Wire`, `TxEip1559Wire`, `ReadPrecompileInput`, `ReadPrecompileResult`, `EvmState`, `SendToEvmData`, etc. |
| `bridge` | 30 | 750 B | `Bridge2`, `BridgeValidatorSet`, `BridgeEpoch`, `BridgeValidator`, `EthEventId`, `VoteEthDepositAction`, `PendingWithdrawals`, `TotalWithdrawal`, etc. |
| `constants` | 4 | 181 B | `Chain::fmt` (`0x1778c60`, 106 B, 70/106 raw-equal, 0 non-relocation diffs) + `StaticConfig` (`0x17785d0`) + `enum Chain` (`0x46ddb50`, `0x57d1bb0`) |
| **Total** | **138** | **6,060 B** | **138/138 (100.00%) relocation-qualified, 0 non-relocation mismatches** |

## Negative Controls

`verify.py --self-test` verifies 4/4 rejection of synthetic mutations:
1. Tampered `target_sha256`
2. Tampered `target_body_sha256` on `0x2744200`
3. Shifted FDE end VA on `0x1778c60`
4. Tampered `expecting_string` on a 25-byte `Visitor::expecting` FDE

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-015-node115-stream-f-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_stream_f_byte_matches_115 -v
(cd research/work-items/RE-015-node115-stream-f-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_packets.py research/work-items/RE-015-node115-stream-f-byte-matches
```
