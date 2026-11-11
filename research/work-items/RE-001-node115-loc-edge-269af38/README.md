# RE-001: map node #115 base/u.rs:531 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x269af38` (file offset `0x2699f38`), `488d1569c6d903` decodes as `lea rdx, [rip + 0x3d9c669]`. Adding the signed displacement `64603753` to the next instruction VA `0x269af3f` yields `0x64375a8`. The decode from the start of FDE range `[0x269ae20, 0x269b095)` reaches that instruction boundary. The FDE itself is at `0x112bdbc`.

At `0x64375a8` (file offset `0x64355a8`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d000000000000001302000009000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 531 and 9. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x269ae94` is `0x269af11` and the fallthrough is `0x269ae96`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rax, rax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x269ae91` | `4885c0` | `test rax, rax` |
| `0x269ae94` | `757b` | `jne 0x269af11` |
| `0x269af11` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x269af16` | `4889542420` | `mov qword ptr [rsp + 0x20], rdx` |
| `0x269af1b` | `488d442418` | `lea rax, [rsp + 0x18]` |
| `0x269af20` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x269af25` | `488d0524cde0ff` | `lea rax, [rip - 0x1f32dc]` |
| `0x269af2c` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x269af31` | `488d3d1f09dafd` | `lea rdi, [rip - 0x225f6e1]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 65292142 added to `0x269af4a` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x269af3f` | `488d742408` | `lea rsi, [rsp + 8]` |
| `0x269af44` | `ff156e47e403` | `call qword ptr [rip + 0x3e4476e]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64375a8 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x269ae20 --stop-address=0x269af4a "$target"
od -An -tx1 -j 105076144 -N 16 "$target"
objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d156ac6d903`), re-decoding lands at `0x64375a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 531, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
