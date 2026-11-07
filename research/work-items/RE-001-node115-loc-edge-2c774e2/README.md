# RE-001: map node #115 l1/dex_registry/dex_registry.rs:37 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/dex_registry.rs` as an embedded path. At ELF VA `0x2c774e2` (file offset `0x2c764e2`), `488d358f448103` decodes as `lea rsi, [rip + 0x381448f]`. Adding the signed displacement `58803343` to the next instruction VA `0x2c774e9` yields `0x648b978`. The decode from the start of FDE range `[0x2c774c0, 0x2c77640)` reaches that instruction boundary. The FDE itself is at `0xd86b7c`.

At `0x648b978` (file offset `0x6489978`), an `R_X86_64_RELATIVE` relocation points to `0x44e909` in `.rodata`. The next 16 bytes, `23000000000000002500000030000000`, decode as a little-endian 64-bit length of 35 and two 32-bit values, 37 and 48. The string's normalized suffix matches `l1/dex_registry/dex_registry.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2c774e0` is `0x2c77503` and the fallthrough is `0x2c774e2`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rbx, qword ptr [r15 + 0x10]`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c774dc` | `493b5f10` | `cmp rbx, qword ptr [r15 + 0x10]` |
| `0x2c774e0` | `7421` | `je 0x2c77503` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 59169204 added to `0x2c774f4` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c774e9` | `bf05000000` | `mov edi, 5` |
| `0x2c774ee` | `ff15b4d98603` | `call qword ptr [rip + 0x386d9b4]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648b978 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c774c0 --stop-address=0x2c774f4 "$target"
od -An -tx1 -j 105421184 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e909 --stop-address=0x44e92c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3590448103`), re-decoding lands at `0x648b979`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 37, column 48. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
