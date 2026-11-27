# RE-005: Node #115 `serialization` (`z_forks/bincode-fork`) Gate-Closure Audit & Compiled-Byte Matches

Component: `serialization` (`z_forks/bincode-fork`).
Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`), SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Scope & Evidence

1. **Complete 19-FDE `z_forks/bincode-fork` CGU inventory (`0x1607c70..0x1609aaa`, `7,575 B` FDE bytes)**:
   - Anchored by the contiguous `.data.rel.ro` vtable block `0x6403160..0x6403308` plus `0x64e1940` (`<DecodeError as Display>::fmt`) and bounded immediately after by `blake3` (`0x1609ab0`).
   - **6/19 CGU FDEs (`196 B`) matched at 100.00% relocation-qualified compiled-byte identity** under `rustc 1.95.0 --edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes`:
     - 4 brand-new CGU FDEs verified in this packet (`105 B`):
       - `0x1609a70..0x1609aaa` (58 B): `<DecodeError as Display>::fmt` (`write!(f, "{self:?}")` -> `0x16087a0`)
       - `0x1608320..0x1608333` (19 B): `<&&str as Debug>::fmt` forwarder (`0x64032a0` -> `0x1689750`)
       - `0x1609310..0x1609323` (19 B): `<&str as Debug>::fmt` forwarder (`0x6403240` -> `0x1689750`)
       - `0x16090f0..0x16090f9` (9 B): `<&std::io::Error as Debug>::fmt` forwarder (`0x64031a0` -> `0x16892a0`)
     - 2 CGU FDEs already verified in `RE-012-node115-stream-c-byte-matches` (`91 B`): `0x1609a40` (`<IntegerType as Debug>::fmt`, 44 B) and `0x1609930` (`<&IntegerType as Debug>::fmt`, 47 B).
   - **12/19 CGU FDEs (`7,170 B`)**: inlined `core::fmt::builders` / `core::fmt::num` formatting bodies (`DecodeError::Debug` `0x16087a0`, `AllowedEnumVariants::Debug` `0x1609100`, `Utf8Error::Debug` `0x1609850`, `Option<u8>::Debug` `0x1609330`, `&[u32]::Debug` `0x1609640`, `[u8; 4]::Debug` `0x1608340`, plus 6 integer `Debug` bodies).
   - **1/19 CGU FDE (`209 B`)**: `0x1609960` `drop_in_place::<std::io::Error>` (jemalloc `sdallocx` GOT `0x64df4a0 -> 0x635de30`).

2. **Four business-logic `z_forks/bincode-fork` varint slow-path FDEs matched at 100.00% relocation-qualified compiled-byte identity (`939 B`, `906/939 = 96.49%` raw-equal)**:
   - `0x5822490..0x58225b5` (**293 B**, 280/293 raw): `bincode::varint::varint_decode_u32_slow` (GOT `0x64e7f78 -> 0x5822700`)
   - `0x58225c0..0x58226fc` (**316 B**, 306/316 raw): `bincode::varint::varint_decode_u64_slow` (GOT `0x64e7f78 -> 0x5822700`)
   - `0x5822700..0x582270e` (**14 B**, 14/14 raw — 100.00% raw-equal): `bincode::varint::cold_invalid_int`
   - `0x5822710..0x582284c` (**316 B**, 306/316 raw): `bincode::varint::varint_decode_usize_slow` (GOT `0x64e7f78 -> 0x5822700`)

3. **Complete 4-path / 13-`Location` / 100-FDE call-site audit**:
   - `z_forks/bincode-fork/src/de/decoder.rs:93:13` (`0x434850`): 3 `Location`s, 27 FDEs
   - `z_forks/bincode-fork/src/de/impls.rs:499:20` (`0x437b43`): 2 `Location`s, 2 FDEs (`0x2cd7d90`, `0x5821540`)
   - `z_forks/bincode-fork/src/enc/write.rs:78:9` (`0x439c31`): 6 `Location`s, 61 FDEs
   - `z_forks/bincode-fork/src/lib.rs:171:22` (`0x444056`): 2 `Location`s, 12 FDEs
   - Total: **100 unique call-site FDEs** across node #115 (`0x2cd7d90` and `0x5821540` reference both `de/impls.rs:499:20` and `de/decoder.rs:93:13`).

4. **Behavioral & corruption closure in `src/bincode-fork/`**:
   - Aligned `DecodeError::fmt` / `EncodeError::fmt` (`Display`) to `write!(f, "{self:?}")` matching `0x1609a70`.
   - Added pure-`std` (`#![forbid(unsafe_code)]`, 0 external deps) `NonZero*` (all 12 widths), `CString`/`CStr`, `SystemTime`, and `IoReader`/`IoWriter` codecs plus boundary/corruption tests covering all 18 `DecodeError` tags (`0..=17`) and all 13 `IntegerType` tags (`0..=12`).

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-005-node115-bincode-fork-gate-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_bincode_fork_gate_closure_115 tests.test_bincode_fork_115 -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/net-runtime \
  cargo +1.95.0 test --offline --locked --manifest-path src/bincode-fork/Cargo.toml
```
