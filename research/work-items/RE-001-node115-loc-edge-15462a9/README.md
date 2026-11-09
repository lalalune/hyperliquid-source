# RE-001: map node #115 base/daily_liner.rs:58 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/daily_liner.rs` as an embedded path. At ELF VA `0x15462a9` (file offset `0x15452a9`), `4c8d054079eb04` decodes as `lea r8, [rip + 0x4eb7940]`. Adding the signed displacement `82540864` to the next instruction VA `0x15462b0` yields `0x63fdbf0`. The decode from the start of FDE range `[0x1546000, 0x1546373)` reaches that instruction boundary. The FDE itself is at `0x104fcdc`.

At `0x63fdbf0` (file offset `0x63fbbf0`), an `R_X86_64_RELATIVE` relocation points to `0x43888a` in `.rodata`. The next 16 bytes, `17000000000000003a00000033000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 58 and 51. The string's normalized suffix matches `base/daily_liner.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x1546251` is `0x154628e` and the fallthrough is `0x1546253`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp byte ptr [rsp + 0xa8], 1`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1546249` | `80bc24a800000001` | `cmp byte ptr [rsp + 0xa8], 1` |
| `0x1546251` | `743b` | `je 0x154628e` |
| `0x154628e` | `488b8424b0000000` | `mov rax, qword ptr [rsp + 0xb0]` |
| `0x1546296` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x154629b` | `488d3d660df2fe` | `lea rdi, [rip - 0x10df29a]` |
| `0x15462a2` | `488d0d2f7beb04` | `lea rcx, [rip + 0x4eb7b2f]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 83465184 added to `0x15462c0` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15462b0` | `488d542410` | `lea rdx, [rsp + 0x10]` |
| `0x15462b5` | `be2b000000` | `mov esi, 0x2b` |
| `0x15462ba` | `ff15e093f904` | `call qword ptr [rip + 0x4f993e0]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fdbf0 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1546000 --stop-address=0x15462c0 "$target"
od -An -tx1 -j 104840184 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43888a --stop-address=0x4388a1 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d054179eb04`), re-decoding lands at `0x63fdbf1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 58, column 51. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
