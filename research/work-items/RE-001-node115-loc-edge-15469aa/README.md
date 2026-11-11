# RE-001: map node #115 base/daily_liner.rs:27 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/daily_liner.rs` as an embedded path. At ELF VA `0x15469aa` (file offset `0x15459aa`), `488d155772eb04` decodes as `lea rdx, [rip + 0x4eb7257]`. Adding the signed displacement `82539095` to the next instruction VA `0x15469b1` yields `0x63fdc08`. The decode from the start of FDE range `[0x1546700, 0x1546a6a)` reaches that instruction boundary. The FDE itself is at `0x104fd9c`.

At `0x63fdc08` (file offset `0x63fbc08`), an `R_X86_64_RELATIVE` relocation points to `0x43888a` in `.rodata`. The next 16 bytes, `17000000000000001b0000000d000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 27 and 13. The string's normalized suffix matches `base/daily_liner.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x1546741` is `0x154698a` and the fallthrough is `0x1546747`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp byte ptr [r14 + r15 - 1], 0x2f`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x154673b` | `43807c3eff2f` | `cmp byte ptr [r14 + r15 - 1], 0x2f` |
| `0x1546741` | `0f8443020000` | `je 0x154698a` |
| `0x154698a` | `488d8424b0000000` | `lea rax, [rsp + 0xb0]` |
| `0x1546992` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x1546997` | `488d0502520a00` | `lea rax, [rip + 0xa5202]` |
| `0x154699e` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x15469a3` | `488d3dad4eeffe` | `lea rdi, [rip - 0x110b153]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 83463420 added to `0x15469bc` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15469b1` | `488d742410` | `lea rsi, [rsp + 0x10]` |
| `0x15469b6` | `ff15fc8cf904` | `call qword ptr [rip + 0x4f98cfc]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fdc08 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1546700 --stop-address=0x15469bc "$target"
od -An -tx1 -j 104840208 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43888a --stop-address=0x4388a1 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d155872eb04`), re-decoding lands at `0x63fdc09`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 27, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
