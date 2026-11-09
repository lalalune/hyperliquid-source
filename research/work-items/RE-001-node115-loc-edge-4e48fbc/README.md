# RE-001: map node #115 base/u.rs:531 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x4e48fbc` (file offset `0x4e47fbc`), `488d153d4b6501` decodes as `lea rdx, [rip + 0x1654b3d]`. Adding the signed displacement `23415613` to the next instruction VA `0x4e48fc3` yields `0x649db00`. The decode from the start of FDE range `[0x4e48ee0, 0x4e4910c)` reaches that instruction boundary. The FDE itself is at `0x1303ee8`.

At `0x649db00` (file offset `0x649bb00`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d000000000000001302000009000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 531 and 9. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x4e48f22` is `0x4e48f95` and the fallthrough is `0x4e48f24`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rax, rax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4e48f1f` | `4885c0` | `test rax, rax` |
| `0x4e48f22` | `7571` | `jne 0x4e48f95` |
| `0x4e48f95` | `4889442418` | `mov qword ptr [rsp + 0x18], rax` |
| `0x4e48f9a` | `4889542420` | `mov qword ptr [rsp + 0x20], rdx` |
| `0x4e48f9f` | `488d442418` | `lea rax, [rsp + 0x18]` |
| `0x4e48fa4` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x4e48fa9` | `488d0570d37c00` | `lea rax, [rip + 0x7cd370]` |
| `0x4e48fb0` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x4e48fb5` | `488d3d9b285ffb` | `lea rdi, [rip - 0x4a0d765]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 23684842 added to `0x4e48fce` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4e48fc3` | `488d742408` | `lea rsi, [rsp + 8]` |
| `0x4e48fc8` | `ff15ea666901` | `call qword ptr [rip + 0x16966ea]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*649db00 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4e48ee0 --stop-address=0x4e48fce "$target"
od -An -tx1 -j 105495304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d153e4b6501`), re-decoding lands at `0x649db01`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 531, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
