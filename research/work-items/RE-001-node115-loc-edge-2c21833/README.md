# RE-001: map node #115 l1/books.rs:19 conditional call edge

- Component allocation: `orderbook`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/books.rs` as an embedded path. At ELF VA `0x2c21833` (file offset `0x2c20833`), `488d3d065d8103` decodes as `lea rdi, [rip + 0x3815d06]`. Adding the signed displacement `58809606` to the next instruction VA `0x2c2183a` yields `0x6437540`. The decode from the start of FDE range `[0x2c20a90, 0x2c219c2)` reaches that instruction boundary. The FDE itself is at `0x118b078`.

At `0x6437540` (file offset `0x6435540`), an `R_X86_64_RELATIVE` relocation points to `0x44e6b2` in `.rodata`. The next 16 bytes, `0f00000000000000130000002f000000`, decode as a little-endian 64-bit length of 15 and two 32-bit values, 19 and 47. The string's normalized suffix matches `l1/books.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2c20c22` is `0x2c21833` and the fallthrough is `0x2c20c28`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r13, qword ptr [r14 + 0x3ae8]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c20c1b` | `4d3baee83a0000` | `cmp r13, qword ptr [r14 + 0x3ae8]` |
| `0x2c20c22` | `0f830b0c0000` | `jae 0x2c21833` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 59498475 added to `0x2c21845` gives the relocation slot `0x64df830`. Its symbol-zero RELATIVE addend is `0x1680c10`. The target's FDE at `0xcc3008` describes `[0x1680c10, 0x1680c29)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c2183a` | `4c8b6c2418` | `mov r13, qword ptr [rsp + 0x18]` |
| `0x2c2183f` | `ff15ebdf8b03` | `call qword ptr [rip + 0x38bdfeb]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6437540 '
readelf -rW "$target" | grep -i '0*64df830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c20a90 --stop-address=0x2c21845 "$target"
od -An -tx1 -j 105076040 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e6b2 --stop-address=0x44e6c1 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d075d8103`), re-decoding lands at `0x6437541`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 19, column 47. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
