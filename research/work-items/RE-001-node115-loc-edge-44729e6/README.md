# RE-001: map node #115 l1/qtys/impl_ntl.rs:70 conditional call edge

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/qtys/impl_ntl.rs` as an embedded path. At ELF VA `0x44729e6` (file offset `0x44719e6`), `488d350b0c0202` decodes as `lea rsi, [rip + 0x2020c0b]`. Adding the signed displacement `33688587` to the next instruction VA `0x44729ed` yields `0x64935f8`. The decode from the start of FDE range `[0x4472010, 0x4472b92)` reaches that instruction boundary. The FDE itself is at `0xebc2fc`.

At `0x64935f8` (file offset `0x64915f8`), an `R_X86_64_RELATIVE` relocation points to `0x43df4b` in `.rodata`. The next 16 bytes, `17000000000000004600000001000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 70 and 1. The string's normalized suffix matches `l1/qtys/impl_ntl.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x44727f6` is `0x44729e6` and the fallthrough is `0x44727fc`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rax, rcx`. The recorded edge is selected when the `jg` predicate (`ZF = 0 and SF = OF`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x44727f3` | `4839c8` | `cmp rax, rcx` |
| `0x44727f6` | `0f8fea010000` | `jg 0x44729e6` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 34022579 added to `0x44729f5` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x44729ed` | `31ff` | `xor edi, edi` |
| `0x44729ef` | `ff15b3240702` | `call qword ptr [rip + 0x20724b3]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64935f8 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4472010 --stop-address=0x44729f5 "$target"
od -An -tx1 -j 105453056 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43df4b --stop-address=0x43df62 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d350c0c0202`), re-decoding lands at `0x64935f9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 70, column 1. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
