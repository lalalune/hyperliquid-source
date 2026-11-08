# RE-001: map node #115 l1/dex_registry/perp_dex.rs:29 conditional call edge

- Component allocation: `dex-registry`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/dex_registry/perp_dex.rs` as an embedded path. At ELF VA `0x2b7ebcb` (file offset `0x2b7dbcb`), `4c8d0536529003` decodes as `lea r8, [rip + 0x3905236]`. Adding the signed displacement `59789878` to the next instruction VA `0x2b7ebd2` yields `0x6483e08`. The decode from the start of FDE range `[0x2b7d0a0, 0x2b7ee4f)` reaches that instruction boundary. The FDE itself is at `0x11861d8`.

At `0x6483e08` (file offset `0x6481e08`), an `R_X86_64_RELATIVE` relocation points to `0x433bb6` in `.rodata`. The next 16 bytes, `1f000000000000001d0000001d000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 29 and 29. The string's normalized suffix matches `l1/dex_registry/perp_dex.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2b7ddfd` is `0x2b7ebb3` and the fallthrough is `0x2b7de03`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [r14 + 0x4640], 0`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2b7ddf5` | `4983be4046000000` | `cmp qword ptr [r14 + 0x4640], 0` |
| `0x2b7ddfd` | `0f84b00d0000` | `je 0x2b7ebb3` |
| `0x2b7ebb3` | `66c78424100100005601` | `mov word ptr [rsp + 0x110], 0x156` |
| `0x2b7ebbd` | `488d3d36aac4fd` | `lea rdi, [rip - 0x23b55ca]` |
| `0x2b7ebc4` | `488d0d75559003` | `lea rcx, [rip + 0x3905575]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 60164795 added to `0x2b7ebe5` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2b7ebd2` | `488d942410010000` | `lea rdx, [rsp + 0x110]` |
| `0x2b7ebda` | `be2b000000` | `mov esi, 0x2b` |
| `0x2b7ebdf` | `ff15bb0a9603` | `call qword ptr [rip + 0x3960abb]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6483e08 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2b7d0a0 --stop-address=0x2b7ebe5 "$target"
od -An -tx1 -j 105389584 -N 16 "$target"
objdump -s -j .rodata --start-address=0x433bb6 --stop-address=0x433bd5 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0537529003`), re-decoding lands at `0x6483e09`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 29, column 29. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
