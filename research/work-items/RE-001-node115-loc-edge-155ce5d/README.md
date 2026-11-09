# RE-001: map node #115 base/cid.rs:28 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/cid.rs` as an embedded path. At ELF VA `0x155ce5d` (file offset `0x155be5d`), `4c8d053c17ea04` decodes as `lea r8, [rip + 0x4ea173c]`. Adding the signed displacement `82450236` to the next instruction VA `0x155ce64` yields `0x63fe5a0`. The decode from the start of FDE range `[0x155cd10, 0x155cec7)` reaches that instruction boundary. The FDE itself is at `0x1051014`.

At `0x63fe5a0` (file offset `0x63fc5a0`), an `R_X86_64_RELATIVE` relocation points to `0x44d4c1` in `.rodata`. The next 16 bytes, `0f000000000000001c00000049000000`, decode as a little-endian 64-bit length of 15 and two 32-bit values, 28 and 73. The string's normalized suffix matches `base/cid.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x155cdcd` is `0x155ce45` and the fallthrough is `0x155cdcf`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp byte ptr [rsp + 0x28], 1`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x155cdc8` | `807c242801` | `cmp byte ptr [rsp + 0x28], 1` |
| `0x155cdcd` | `7476` | `je 0x155ce45` |
| `0x155ce45` | `488b442430` | `mov rax, qword ptr [rsp + 0x30]` |
| `0x155ce4a` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x155ce4f` | `488d3d25aaf0fe` | `lea rdi, [rip - 0x10f55db]` |
| `0x155ce56` | `488d0d831aea04` | `lea rcx, [rip + 0x4ea1a83]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 83372076 added to `0x155ce74` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x155ce64` | `488d542408` | `lea rdx, [rsp + 8]` |
| `0x155ce69` | `be2b000000` | `mov esi, 0x2b` |
| `0x155ce6e` | `ff152c28f804` | `call qword ptr [rip + 0x4f8282c]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fe5a0 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x155cd10 --stop-address=0x155ce74 "$target"
od -An -tx1 -j 104842664 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44d4c1 --stop-address=0x44d4d0 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d053d17ea04`), re-decoding lands at `0x63fe5a1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 28, column 73. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
