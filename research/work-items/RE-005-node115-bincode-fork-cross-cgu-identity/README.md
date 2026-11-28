# RE-005: Node #115 `serialization` (`z_forks/bincode-fork`) Cross-CGU Standalone Primitive Identity & 100-FDE Partition

- **Target**: Linux x86-64 `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `serialization` (`z_forks/bincode-fork`).
- **Toolchain**: `rustc 1.95.0 (59807616e 2026-04-14)`, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"` + cross-crate `rlib` instantiations, `#![forbid(unsafe_code)]`, 0 external crates.io dependencies.
- **Static analysis only**: The captured binary is neither executed nor emulated.

## Summary

Closes the cross-CGU `z_forks/bincode-fork` audit requested in `@validator` `#329` and `@deps-forks` `#331`:

1. **26 Newly Matched Standalone Cross-CGU `bincode_fork` Primitive FDEs (`4,168 B`)**:
   - **26/26** exact `.eh_frame` FDE extents matched at **100.00% relocation-qualified compiled-byte identity** (0 non-relocation diffs, `3,962 / 4,168 = 95.06%` raw-equal bytes, including **4 completely 100%-raw-equal FDEs = 421 B**: `0x2cd7960` `<u8 as Decode>::decode`, `0x2cd7ca0` & `0x5821430` `<[u8; 32] as Decode>::decode`, `0x2cd7d20` `<[u8; 20] as Decode>::decode`).
   - **100% first-party `bincode_fork` attribution**: Every symbol is defined in `bincode_fork` (enforced by `verify.py`; zero `core::`/`alloc::`/`std::` attribution).
   - **0 overlaps**: Verified disjoint internally, against `research/byte-windows.json`, and against all sibling compiled-byte work-item packets across all VA key spellings.
   - Independently re-verifies the 1 already-claimed standalone cross-CGU `bincode_fork` FDE `0x29360e0..0x293617b` (`155 B`, `node115-w2-thinlto-29360e0`) without double-claiming it in `records.json`.

2. **Exhaustive 100-FDE Cross-CGU `bincode-fork` `Location` Partition (`61,605 B`)**:
   - Authenticates all **13** `z_forks/bincode-fork/src/*.rs` `core::panic::Location` structs in `.data.rel.ro` and all **100** cross-CGU `.text` FDEs (outside the dedicated CGU `0x1607c70..0x1609aaa`) referencing them:
     - **11 standalone `serialization`-owned `bincode_fork` FDEs (`1,946 B`)**:
       - `8` (`772 B`) newly matched at 100.00% in this packet (`0x27880f0`, `0x58220e0`, `0x5822160`, `0x5822370`, `0x58223a0`, `0x5822460`, `0x5822850`, `0x5822b90`).
       - `1` (`155 B`) already claimed in `research/byte-windows.json` (`0x29360e0`) and independently re-verified here.
       - `2` (`1,019 B`) `<[u64; 4] as Decode>::decode` FDEs (`0x2cd7d90` `540 B` & `0x5821540` `479 B`), transparently excluded from compiled-byte claims (reproduced at exact `540 B` extent / `505/540` raw-equal with a 3-byte `cmpb $0x0` vs `cmpl $0x1` LLVM InstCombine `Option<usize>` range-narrowing diff at offsets `[20, 22, 23]`).
     - **89 caller-crate composite monomorphizations (`59,659 B`)**:
       - `9` Tokio `runtime_mt.rs` async task wrappers (`14,459 B`)
       - `3` caller-type `decode_from_slice` instantiations (`2,032 B`, `EvmKvsMsg` / `AbciStreamGreeting` / 2-field struct)
       - `25` caller-struct `Vec<CallerT>` / composite decoders (`16,331 B`)
       - `9` caller `BTreeMap`/`BTreeSet<CallerK, CallerV>` encoders (`7,535 B`)
       - `43` caller-struct / `VecDeque` / `Option` `SizeWriter` encoders (`19,302 B`)

3. **Cumulative `serialization` (`z_forks/bincode-fork`) Verified Compiled-Byte Total**:
   - Dedicated CGU (`0x1607c70..0x1609aaa`, `RE-005-node115-bincode-fork-cgu-100pct-identity`): **19/19 FDEs = 7,575 B (100.00%)** + `.rodata`/`.data.rel.ro`/vtable/GOT identity.
   - Cross-CGU slow varint decoders (`RE-005-node115-bincode-fork-gate-closure`, in `byte-windows.json`): **4 FDEs = 939 B**.
   - Cross-CGU Wave-2 `varint_encode_u64` (`0x29360e0`, in `byte-windows.json`): **1 FDE = 155 B**.
   - Cross-CGU standalone primitives (this packet): **26 FDEs = 4,168 B**.
   - **Total**: **50 verified `serialization` FDEs = 12,837 B** (only the 2 documented `[u64; 4]::decode` FDEs = 1,019 B remain outside exact compiled-byte claims).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-005-node115-bincode-fork-cross-cgu-identity/verify.py --rebuild --self-test
(cd research/work-items/RE-005-node115-bincode-fork-cross-cgu-identity && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_bincode_fork_cross_cgu_identity_115 -v
```
