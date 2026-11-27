# RE-001: Node #115 `foundation` (`base`) First-Party Compiled-Byte FDE Matches

- **Component ID**: `foundation` (`base`, Stream A, `RE-001`)
- **Target Artifact**: `artifacts/node/115/hl-node` (Linux x86-64 ELF, 105,896,032 bytes)
- **Target SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Toolchain**: `rustc 1.95.0 (59807616e 2026-04-14)` (`--edition=2021 -C opt-level=3 -C overflow-checks=yes`; `lib.rs` compiled as `--crate-type=rlib` and `thinlto.rs` compiled with `-C lto=thin -C codegen-units=1 -C save-temps`, matching node #115's ThinLTO + overflow-checks release profile).
- **Claim Status**: Statically verified against the authenticated node #115 ELF (never executed). All **69 first-party `foundation` (`base`) FDE windows (`9,450 B`)** are 100.00% relocation-qualified (`0` non-relocation byte mismatches across all 69 FDEs), verified against `work/index/node-115-fde.tsv`, and strictly disjoint from all dependency windows, partial overlaps in `research/byte-windows.json`, and all sibling `*-byte-matches` / `RE-015-node115-constants-gate-closure` packets. Does not claim full-component `foundation` acceptance gates.

## Summary of Matched First-Party `foundation` (`base`) FDEs

| Category | Build Mode | Windows | Total Bytes | Highlights |
| --- | --- | ---: | ---: | --- |
| Business logic | `rlib` | 1 | 89 B | `base/src/short_string.rs:52` (`0x15472b0..0x1547309`, recursive `u128` byte packer with checked `* 256`) |
| First-party enum `Debug` | `thinlto` | 2 | 98 B | `Crate` (`0x1534270`, 47 B, all 13 workspace crates `Base..EvmRpc`), `PhraseCheckError` (`0x1544470`, 51 B) |
| First-party struct `Debug` | `thinlto` | 36 | 8,513 B | `LogSettings` (2 FDEs, 508 B + 505 B = 1,013 B), `Signature` (5 FDEs, 1,303 B), `CodeLocation` (8 FDEs, 1,768 B), `LockLocation` (8 FDEs, 1,768 B), `LockId` (4 FDEs, 896 B), `LockOrderWitness` (4 FDEs, 884 B), `LockOrderingViolation` (4 FDEs, 660 B), `ZipInnerArgs` (1 FDE, 221 B) |
| First-party `Visitor::expecting` | `thinlto` | 30 | 750 B | `BugAlertAck`, `Ignore`, `Signature` (7), `Time` (4), `ApiSecrets`, `SignedIndexedUpload` (2), `VisorMetadata` (2), `HotfixArgs` (2), `HotfixMetadata` (2), `PublisherBinaryMetadata` (2), `BucketGuard` (6) |
| **Total** | | **69** | **9,450 B** | **69/69 relocation-qualified, 0 non-reloc mismatches** |

## Exact Binary Type Layouts Recovered

- `base/src/short_string.rs:52` (`0x15472b0..0x1547309`, 89 B): `if idx == bytes.len() { return 0; } u128::from(bytes[idx]) + short_string_pack_rec(bytes, idx + 1) * 256` (panic `Location`s at `0x63fdc68` `short_string.rs:52:9` and `0x63fdc80` `short_string.rs:52:28`).
- `base/src/log/settings.rs` (`LogSettings`, `0x1544270` 508 B & `0x15528b0` 505 B): 7 fields `level`, `err_fln`, `stdout_fln`, `throttle`, `log_to_stdout`, `n_overflow_files`, `custom_dir`.
- `base/src/lock_id.rs` (`CodeLocation { fln, line }`, `LockId { inner, deadlock_detection }`, `LockLocation { id, call_location }`, `LockOrderWitness { a_lock_code_location, b_lock_code_location }`, `LockOrderingViolation { reverse_edge, reverse_witness, lock_a, lock_b }`).
- `base/src/wallet.rs` (`Signature { r, s, v }`), `base/src/fu.rs` (`ZipInnerArgs { silent, remove_orig }`), and `Crate` (`Base`, `PeriBase`, `Infra`, `Live`, `Nexus`, `Trade`, `Nn`, `L1`, `Node`, `Peripheral`, `NetUtils`, `Db`, `EvmRpc`).

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-foundation-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_foundation_byte_matches_115 -v
(cd research/work-items/RE-001-node115-foundation-byte-matches && sha256sum -c MANIFEST.sha256)
```
