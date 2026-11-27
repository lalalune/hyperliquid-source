# RE-005: Node #115 `z_forks/bincode-fork` codec reconstruction

Component: `serialization`. Target: Linux x86-64 node #115 (`artifacts/node/115/hl-node`),
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Binary Observations

1. **Four observed `z_forks/bincode-fork` source paths in `.rodata` and `.data.rel.ro` (`core::panic::Location`)**:
   - `0x434850`: `z_forks/bincode-fork/src/de/decoder.rs` — `Location` at `0x642e2a0`, `0x644f3a0`, `0x64b0ff0` (`line 93, col 13`), referenced on `bytes_read` subtraction underflow (`unclaim_bytes_read`, e.g., `0x5821712`, `0x5824527..0x5826376`).
   - `0x437b43`: `z_forks/bincode-fork/src/de/impls.rs` — `Location` at `0x644f218`, `0x64b0f08` (`line 499, col 20`), referenced by `core::option::unwrap_failed` (`0x1680c10`) during fixed-array decoding (`0x5821705`).
   - `0x439c31`: `z_forks/bincode-fork/src/enc/write.rs` — `Location` at `0x642dbd0`, `0x643b688`, `0x6440bd8`, `0x64a1e28`, `0x64b0ef0`, `0x64bcb78` (`line 78, col 9`), referenced on `SizeWriter::write` checked-add overflow (`0x1681da0`, e.g., `0x58228f7`, `0x5822c37`).
   - `0x444056`: `z_forks/bincode-fork/src/lib.rs` — `Location` at `0x64377f0`, `0x64b0f20` (`line 171, col 22`), referenced on `decode_from_slice` remaining-length subtraction (`slice.len() - remaining.len()`, e.g., `0x26feb16`, `0x5821ed9`).

2. **Complete 18-variant `DecodeError` enum (`0x16087a0..0x16090ed`, jump table `0x46a86c`)**:
   - Tag `0`: `UnexpectedEnd { additional }` (`0x16087c8`)
   - Tag `1`: `InvalidBytesLength` (`0x1608b9e`) — **Hyperliquid fork addition**
   - Tag `2`: `LimitExceeded` (`0x1608a2a`)
   - Tag `3`: `InvalidIntegerType { expected, found }` (`0x1608aba`)
   - Tag `4`: `NonZeroTypeIsZero { non_zero_type }` (`0x1608902`)
   - Tag `5`: `UnexpectedVariant { type_name, allowed, found }` (`0x1608c29`)
   - Tag `6`: `Utf8 { inner }` (`0x1608d13`)
   - Tag `7`: `InvalidCharEncoding` (`0x1608b37`)
   - Tag `8`: `InvalidBooleanValue` (`0x1608e22`)
   - Tag `9`: `ArrayLengthMismatch { required, found }` (`0x16089bd`)
   - Tag `10`: `OutsideUsizeRange` (`0x1608dba`)
   - Tag `11`: `EmptyEnum { type_name }` (`0x16088b3`)
   - Tag `12`: `InvalidDuration { secs, nanos }` (`0x1608950`)
   - Tag `13`: `InvalidSystemTime { duration }` (`0x1608cc7`)
   - Tag `14`: `CStringNulError { position }` (`0x1608873`)
   - Tag `15`: `Io { inner, additional }` (`0x1608a46`)
   - Tag `16`: `Other` (`0x1608817`)
   - Tag `17`: `OtherString` (`0x1608bc4`)
   - `Result<T, DecodeError>::Ok` uses discriminant `18` (`0x12`), observed in `0x5821150`, `0x5821250`, `0x5821340`, `0x5821940`, `0x5821aa0`.

3. **Complete 13-variant `IntegerType` table (`0x6403308` / `0x46aa30`, formatter `0x1609930`)**:
   - `0=U8, 1=U16, 2=U32, 3=U64, 4=U128, 5=Usize, 6=I8, 7=I16, 8=I32, 9=I64, 10=I128, 11=Isize, 12=Reserved`.

4. **Hyperliquid Fork Divergence (`InvalidBytesLength`, `0x5821b1c..0x5821da5`)**:
   - In `0x5821aa0` variant 0 (`0x5821b1c`), after reading varint length `len` (`0x5821b26 -> 0x5821250`) and charging `len` against the configured limit (`0x5821b40..0x5821b62`, returning tag `2 = LimitExceeded` on overflow or `> limit`), the decoder checks `remaining - len` (`0x5821b64..0x5821b6c`: `mov 0x30(%rsp), %r15; sub %rdx, %r15; jae 0x5821d4b`) BEFORE allocating heap storage.
   - If `remaining < len`, it immediately sets tag `1` (`0x5821b72: movb $0x1, %r12b`, `DecodeError::InvalidBytesLength`) without allocating.
   - Generic `Vec<T>` decoding (`0x5824570`) caps initial preallocation to `1_048_576 / size_of::<T>()` (`0x58245fe: cmpq $0xa3d, %r12` for 400-byte elements) and calls `unclaim_bytes_read` before each element.

5. **Varint Codec Cluster (`0x5821150..0x5822c44`)**:
   - `0x5821150` / `0x5822490`: `u32` varint reader (fast `> 4`, slow `<= 4`)
   - `0x5821250` / `0x58225c0`: `u64` varint reader (fast `> 8`, slow `<= 8`)
   - `0x5821340` / `0x5822710`: `usize` varint reader (`expected = Usize(5)`)
   - `0x5822700`: `InvalidIntegerType` raw error constructor (`tag = 3`)
   - `0x5822850` / `0x5822b90`: `SizeWriter` varint size writer (`Ok` tag = `8`)
   - `0x5822910`: `VecWriter` varint buffer writer

## Implementation & Limits

Independently authored MIT crate in `src/bincode-fork/` integrating the core codec and re-exporting verified node #115 serialization micro-crates (`wire_compat`).
Compiled object-code identity against node #115 `.text` windows and dynamic execution of the captured binary are out of scope for this packet.

## Reproduce

```sh
python3 -m unittest tests/test_bincode_fork_115.py
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/net-runtime \
  cargo test --manifest-path src/bincode-fork/Cargo.toml
```
