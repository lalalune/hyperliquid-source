# RE-009: Node #115 `LtHash` Incremental Homomorphic BLAKE3-XOF Math & Hardfork Version Check

- **Target**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`)
- **Work item**: `RE-009` (`storage` + `abci`)
- **Methodology**: Static ELF/`.text`/`.rodata` analysis only; no captured binary execution.

## Binary-Proven Facts

1. **`LtHash` & `LtHashes` exact structure (`0x36c5b50..0x36c5ce5`, `.rodata 0x793711`, `0x793dc1`, `0x459eb4`)**
   - `LtHashes` has 3 fields persisted to `<db_home>/checkpoint/<height>/lt_hashes.json`: `accounts_hash`, `contracts_hash`, `storage_hash`.
   - `LtHash` (`0x810` = 2,064 B) has 3 fields serialized in order: `n_elements` (`+0x800`), `n_bytes` (`+0x808`), and `hash` (`+0x000..+0x800`, 2,048 bytes).

2. **`LtHash` element expansion via standard unkeyed BLAKE3 XOF (`0x36c6100..0x36c628e`)**
   - Initializes standard unkeyed `blake3::Hasher` (`IV` at `0x457ae0..0x457b00`), updates with encoded bytes (`0x64df510`), calls `finalize_xof()` (`0x160ab60`), and fills a `0x800`-byte (2,048 B) buffer via `OutputReader::fill` (`0x64e1978`, `0x1609e70`).

3. **Big-endian `u16` lane homomorphic arithmetic (`0x3c27a20..0x3c27b98`, `0x3c27ba0..0x3c27d08`, `0x3c287d0..0x3c28a81`)**
   - Unlike little-endian LtHash variants, node #115 byte-swaps every 16-bit lane (`psrlw 8; psllw 8; por`) before and after `paddw` (`mix_in`, `0x3c289d0..0x3c28a27`) and `psubw` (`mix_out`, `0x3c27b10..0x3c27b70`) across all `0x400` (1,024) lanes.
   - `mix_in` saturating-increments `n_elements` and `n_bytes`; `mix_out` saturating-decrements `n_elements` and `n_bytes`; updates (`0x3c287d0`) call `mix_out(old)` then `mix_in(new)`.

4. **`LtHash` rebuild batch & 32-byte BLAKE3 checksum (`0x3c27f30..0x3c28210`)**
   - Restores saved `0x810`-byte `LtHash` when `Some`, otherwise scans RocksDB in `0xf4240` (`1,000,000`) batches (`0x3c27fd4`) and computes the 32-byte digest `blake3::hash(&lt_hash.hash[..0x800])` (`0x3c2808d..0x3c280af`).

5. **State hardfork version check (`0x595aff0..0x595b1a0`)**
   - Compares loaded state hardfork version `[rsp + 0x40]` against expected version `rbx` (`0x595b0fa..0x595b10b`), returning `"unexpected state hardfork version: "` (`0x431d7a` via `0x595b135`) on mismatch.

## Reproducibility

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-lthash-homomorphic-and-hardfork-version/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests.test_lthash_homomorphic_and_hardfork_115
```
