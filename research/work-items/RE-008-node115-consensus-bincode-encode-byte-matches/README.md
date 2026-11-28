# RE-008: Node #115 First-Party `consensus` `bincode-fork` `Encode` Compiled-Byte FDE Matches

## Target

- Binary: `artifacts/node/115/hl-node` (Linux x86-64 ELF, `105,896,032` bytes)
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Analysis method: strictly static disassembly, ELF `.eh_frame` FDE bounds (`work/index/node-115-fde.tsv`), and live offline compilation with `rustc +1.95.0` (`--edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes -C relocation-model=pie -C lto=off --emit=obj`, `#![forbid(unsafe_code)]`, zero external crates.io dependencies). Captured binaries are never executed.

## Direct Observations

1. **23 complete, strictly disjoint `.text` FDEs (`6,916` bytes total)** in Linux x86-64 node #115 compile to `100.00%` relocation-qualified matches (`6,330 / 6,916 = 91.53%` raw-equal bytes, `0` non-relocation byte differences) under `tools/byte_progress.py::compare` from a single safe Rust source file (`consensus_encode.rs`):
   - **Quorum certificate (`Qc`) encoders (3 FDEs / `1,017 B`)**: `0x5966770..0x59668c3` (`339 B`, `&mut SizeWriter`), `0x59668d0..0x5966a23` (`339 B`, `SizeWriter`), `0x5966a30..0x5966b83` (`339 B`, `VecWriter`).
   - **Block header (`BlockHeader`) encoders (2 FDEs / `606 B`)**: `0x5966b90..0x5966cc1` (`305 B`, `VecWriter`), `0x5966cd0..0x5966dfd` (`301 B`, `SizeWriter`).
   - **Block (`Block` with `Cert::Qc | Cert::Tc(TcCert)`) encoders (3 FDEs / `1,632 B`)**: `0x5966e40..0x5967054` (`532 B`, `&mut SizeWriter`), `0x5967060..0x596728e` (`558 B`, `VecWriter`), `0x5967290..0x59674ae` (`542 B`, `SizeWriter`).
   - **Timeout-certificate vote (`TcVote`) encoders (2 FDEs / `493 B`)**: `0x59676c0..0x59677ba` (`250 B`, `VecWriter`), `0x59677c0..0x59678b3` (`243 B`, `SizeWriter`).
   - **Timeout (`Timeout`) encoders (2 FDEs / `454 B`)**: `0x5967d90..0x5967e75` (`229 B`, `VecWriter`), `0x5967e80..0x5967f61` (`225 B`, `SizeWriter`).
   - **Consensus signature (`Signature`: 8 `u64` limbs + recovery byte) encoders (2 FDEs / `601 B`)**: `0x5967f70..0x596809e` (`302 B`, `SizeWriter`), `0x59680a0..0x59681cb` (`299 B`, `&mut SizeWriter`).
   - **Consensus optional-payload encoders (`Option<Qc>`, `Option<(Block, Qc)>`, `Option<HorizonMapAndTail>`, `Option<HorizonState>`) + `HorizonInner` encoder (9 FDEs / `2,113 B`)**:
     - `0x4e05490..0x4e05550` (`192 B`, `SizeWriter`), `0x4e05550..0x4e055cf` (`127 B`, `SizeWriter`), `0x4e055d0..0x4e056f3` (`291 B`, `VecWriter`), `0x4e05700..0x4e057dc` (`220 B`, `VecWriter`), `0x4e057e0..0x4e05937` (`343 B`, `VecWriter`), `0x4e05940..0x4e059c3` (`131 B`, `&mut SizeWriter`), `0x4e059d0..0x4e05ac2` (`242 B`, `SizeWriter`), `0x4e05ad0..0x4e05c0d` (`317 B`, `VecWriter`), `0x59cdf40..0x59ce03a` (`250 B`, `VecWriter`).
2. **Direct `.text` call-target anchors**: every FDE's direct `callq` instruction targets in `artifacts/node/115/hl-node` are explicitly checked by `verify.py` (including mutual intra-consensus calls `Block::encode -> Qc::encode`, `Block::encode -> Option<Qc>::encode`, `TcVote::encode -> Qc::encode`, `Option<(Block, Qc)>::encode -> Qc::encode`, `Option<HorizonState>::encode -> HorizonInner::encode -> Option<HorizonMapAndTail>::encode`, and `bincode-fork` writer helpers `0x5822850`/`0x5822b90`/`0x5822910`/`0x58221e0`/`0x58223a0`).
3. **Zero overlaps & zero stdlib attribution**: all 23 FDEs are attributed strictly to first-party `consensus` (zero `core::`/`alloc::`/`std::` or vendored dependency attribution) and have `0` overlaps internally, against `research/byte-windows.json`, and against all sibling compiled-byte match / census / thinlto / wave / identity / gate-closure packets.

## Inferences

- Node #115's `bincode-fork` `EncodeError` uses an 8-variant enum (`Ok(())` discriminant = `8`, size = `32` bytes), and `EncoderImpl<W>` lays out a 16-byte configuration header at `+0x00..+0x10` followed by `writer: W` at `+0x10`.
- `L1Map<K, V>` (`Small(VecDeque<(K, V)>) | Large(BTreeMap<K, V>)`) reserves the `VecDeque` capacity niche `0x8000_0000_0000_0000` for `Large`, leaving niche `0x8000_0000_0000_0001` for outer enums (`Cert::Qc`, `Option<Qc>`, `Option<HorizonMapAndTail>`).
- `HorizonInner` (`0x59cdf40`) contains an `Option<HorizonTail>` with non-niched 4-byte discriminant `0 | 1` at `+0x00`, so `Option<HorizonState>` (`0x4e05ad0`) uses niche `2` at `+0x00`.
- `VecWriter::write` calls `Vec::extend_from_slice` (lowering the growth cold path to `RawVecInner::reserve::do_reserve_and_handle` at `0x5963a10` with `(additional=1, align=1, size=1)`).

## Unknowns and Limits

- Relocated call targets (`bincode-fork` varint/slice primitives, `L1Map` inner `VecDeque`/`BTreeMap` encoders, `NaiveDateTime` encoder, `HorizonTail` encoder, and `RawVecInner::reserve::do_reserve_and_handle`) are modeled as `#[inline(never)]` ABI stubs in `consensus_encode.rs`; their own FDE bodies are outside the 23 claimed windows (several `bincode-fork` primitives are independently matched by `RE-005-node115-bincode-fork-cross-cgu-identity`).
- `<Signature as Encode>::encode<VecWriter>` (`0x59681d0`, `354 B`) is excluded from this packet because its `+0x40` field access loads through an additional indirection not modeled here; it remains open for a follow-up slice.
- `HorizonInner` / `HorizonState` / `HorizonMapAndTail` field names are descriptive labels inferred from adjacent consensus `0x59cd...`/`0x5b56...` strings (`"Unexpected proposer for block"`, `"horizon_state"`), not symbol-table names (node #115 is stripped).

## Reproduction

```bash
cd research/work-items/RE-008-node115-consensus-bincode-encode-byte-matches && sha256sum -c MANIFEST.sha256
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-consensus-bincode-encode-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_consensus_bincode_encode_byte_matches_115 -v
```
