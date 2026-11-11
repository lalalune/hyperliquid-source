# RE-007: node #115 clearinghouse notional ratio

- Component: `risk` (Clearinghouses and risk). Bounded function-map and arithmetic model.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: what does the body that owns `l1/src/clearinghouse/clearinghouse.rs:179:98` compute on its normal return, including the index, the scaled ratio and the two saturating subtractions?
- Claim status: byte-derived observations, one integer proof of the divisor, and an independently authored Rust model of the normal-return arithmetic. No panic ABI, caller-loop closure, MXCSR image, or progress gate.

## Exact scope

| Role | Complete FDE | Bytes | Instructions | Claim |
| --- | --- | ---: | ---: | --- |
| Ratio body | `0x44dcf80..0x44dd1a4` | 548 | 138 | normal-return arithmetic below |
| Sole direct caller | `0x3db8470..0x3db8983` | 1,299 | 293 | call-site registers only |

Export denominator: **1,847 bytes / 431 instructions**. These are retained evidence extents, not reconstructed coverage. A `.text` scan finds one direct `e8` to `0x44dcf80`, at `0x3db8525`, and `.rela.dyn` has no addend equal to that entry. The caller export keeps the surrounding loop without treating its other calls as recovered.

## Index and record field

`rdx` enters as an unsigned key and is preserved in `rbx`. The multiplier immediate `0x346dc5d63886594b` is `ceil(2^75 / 10000)`. The `mul` / `shr rdx, 11` sequence is `floor(key * magic / 2^75)`, and `10000 * magic = 2^75 + 432`. For every `key < 2^64` the positive error stays below one remainder step:

`9999 * 2^75 + (2^64 - 1) * 432 < 10000 * 2^75`.

The index is therefore `key % 10000`. The quotient is discarded. `[r8+0x10]` is the record count and `[r8+0x8]` is the base. An index at or above the count loads `oracle.rs:433:18` and calls `0x64df620 -> 0x1680cbf` at `0x44dd19e`, the last instruction of the FDE. Each admitted record is 96 bytes (`lea` by 3, then `shl 5`). The signed word at record+0x20 is the field.

A negative field, or a signed `imul` by `[rcx+0x10]` that sets the overflow flag, reaches `0x44dd116`. That edge loads `clearinghouse.rs:179:98` and calls `0x64df830 -> 0x1680c10`. The next address, `0x44dd123`, is the overflow block of the later subtraction, so this packet does not assign a numeric result to a helper that returns. `i64::MIN` as a product of `1 * i64::MIN` does not set that overflow flag; its bit pattern is the unsigned magnitude `2^63`.

## Scaled ratio

`[[input+0x08]] == 0` stores tag word 0 through the shared `[rdi] = rax` at `0x44dd101` and returns. The other output words and the balance word stay unchanged.

Otherwise the numerator is the unsigned magnitude of the product, converted with the `punpckldq` / `subpd` / `addsd` sequence whose pool constants are `0x4530000043300000`, `2^52` and `2^84`. The denominator uses the same unsigned conversion. The scale at `[[input+0x18]]` uses `cvtsi2sd`. The arithmetic order is `divsd` of the magnitude by the denominator, then `mulsd` by the scale.

Absolute bits above `0x7fefffffffffffff` force the value to zero before conversion. Admitted inputs cannot reach that edge: the magnitude is at most `2^63`, the scale magnitude is at most `2^63`, and the denominator is at least 1, so the binary64 product stays near `2^126`. Finite values are clamped to `[-2^63, 2^63]` (`0xc3e0000000000000` and `0x43e0000000000000`) with `maxsd` / `minsd`. `cvttsd2si` truncates toward zero. A value above `0x43dfffffffffffff` (the encoding immediately below `2^63`) is replaced by `i64::MAX`. The following orderedness `cmovnp` keeps that integer for every finite clamped value.

The body does not write MXCSR. Inexact quotients follow the surrounding rounding mode. The Rust model uses IEEE round-ties-even, which is the SysV default, and locks one order-sensitive case at bits `0x4352aaaaaaaaaaaa`.

## Stores

Both subtractions saturate. Overflow calls `0x64e4ea8 -> 0x4524e40` with `l1/src/qtys/impl_ntl.rs:70:1` and, when that helper returns, continues with the saturated word (`i64::MAX` when the mathematical result is too large, `i64::MIN` when it is too small). `converted - product` is the output difference. `*(*(input+0x20)) - converted` is stored back through that pointer.

On the applied return the five little-endian words at `rdi` are:

| Offset | Word |
| --- | --- |
| +0 | tag `1` |
| +8 | original key |
| +0x10 | multiplier from `[rcx+0x10]` |
| +0x18 | saturating `converted - product` |
| +0x20 | signed product |

The sole caller builds the input pointer from `caller_rsi+0x48` (`0x3db8487`, stored at `0x3db8494`) and passes that slot's address in `rsi`. It skips the call when `[rcx+0x10]` is zero (`0x3db8510`) and passes the key from `[rax]` (`0x3db851c`). After the return it tests the low byte of the stack output at `rsp+0x40` (`0x3db852a`). The caller's later loop, allocation and second use of the same Location at `0x3db892c` are retained in the export and are not given semantics here.

## Rust model

`src/node115-clearinghouse-ntl-ratio` is an independently authored `no_std` library. `apply` returns `Absent`, `Applied`, or an error for the three non-returning edges. `Applied` carries both saturation flags so a returning `impl_ntl.rs:70` helper is explicit. It does not reproduce the native diagnostic ABI or the caller.

## Reproduce

Ubuntu, Python 3.12, GNU binutils 2.42, rustc 1.95.0:

```sh
python3 research/work-items/RE-007-node115-clearinghouse-ntl-ratio/collect.py \
  --output work/node115-clearinghouse-ntl-ratio --check
python3 -m unittest discover -s tests -p test_node115_clearinghouse_ntl_ratio.py -v
cargo test --locked --offline --manifest-path src/node115-clearinghouse-ntl-ratio/Cargo.toml
```

The collector hashes the node image before parsing, checks the FDE extents against `readelf -wf`, and requires every anchor to be a decoded instruction start. Corruption controls flip anchor bytes in a private `bytearray`. No captured instruction stream is executed.

## Limits

No component gate is requested. `requested_gates` stays empty and the risk gates remain false. Original field names, price or notional units, the caller's record source, and the three diagnostic helpers remain unresolved. The next question is what the caller does with the five output words after the low-byte test, and which object supplies `[rax]` as the key.
