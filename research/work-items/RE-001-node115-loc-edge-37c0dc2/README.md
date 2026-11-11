# RE-001: map node #115 l1/clearinghouse/margin_table.rs:145 conditional call edge

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/clearinghouse/margin_table.rs` as an embedded path. At ELF VA `0x37c0dc2` (file offset `0x37bfdc2`), `488d3d9fd5ca02` decodes as `lea rdi, [rip + 0x2cad59f]`. Adding the signed displacement `46847391` to the next instruction VA `0x37c0dc9` yields `0x646e368`. The decode from the start of FDE range `[0x37c0bf0, 0x37c0dd1)` reaches that instruction boundary. The FDE itself is at `0x12137cc`.

At `0x646e368` (file offset `0x646c368`), an `R_X86_64_RELATIVE` relocation points to `0x4441e4` in `.rodata`. The next 16 bytes, `24000000000000009100000069000000`, decode as a little-endian 64-bit length of 36 and two 32-bit values, 145 and 105. The string's normalized suffix matches `l1/clearinghouse/margin_table.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x37c0ccf` is `0x37c0dc2` and the fallthrough is `0x37c0cd5`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp eax, 2`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x37c0ccc` | `83f802` | `cmp eax, 2` |
| `0x37c0ccf` | `0f85ed000000` | `jne 0x37c0dc2` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 47311457 added to `0x37c0dcf` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x37c0dc9` | `ff1561ead102` | `call qword ptr [rip + 0x2d1ea61]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*646e368 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x37c0bf0 --stop-address=0x37c0dcf "$target"
od -An -tx1 -j 105300848 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4441e4 --stop-address=0x444208 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3da0d5ca02`), re-decoding lands at `0x646e369`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 145, column 105. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
