# RE-001: map node #115 l1/exchange/impl_vault.rs:154 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_vault.rs` as an embedded path. At ELF VA `0x559c077` (file offset `0x559b077`), `488d3d62e3f000` decodes as `lea rdi, [rip + 0xf0e362]`. Adding the signed displacement `15786850` to the next instruction VA `0x559c07e` yields `0x64aa3e0`. The decode from the start of FDE range `[0x559ac10, 0x559c260)` reaches that instruction boundary. The FDE itself is at `0x135b47c`.

At `0x64aa3e0` (file offset `0x64a83e0`), an `R_X86_64_RELATIVE` relocation points to `0x43f171` in `.rodata`. The next 16 bytes, `1d000000000000009a0000003f000000`, decode as a little-endian 64-bit length of 29 and two 32-bit values, 154 and 63. The string's normalized suffix matches `l1/exchange/impl_vault.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x559b457` is `0x559c06f` and the fallthrough is `0x559b45d`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rcx, rcx`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x559b454` | `4885c9` | `test rcx, rcx` |
| `0x559b457` | `0f84120c0000` | `je 0x559c06f` |
| `0x559c06f` | `48c7042400000000` | `mov qword ptr [rsp], 0` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 16005031 added to `0x559c089` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x559c07e` | `488b6c2410` | `mov rbp, qword ptr [rsp + 0x10]` |
| `0x559c083` | `ff15a737f400` | `call qword ptr [rip + 0xf437a7]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa3e0 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x559ac10 --stop-address=0x559c089 "$target"
od -An -tx1 -j 105546728 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43f171 --stop-address=0x43f18e "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d63e3f000`), re-decoding lands at `0x64aa3e1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 154, column 63. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
