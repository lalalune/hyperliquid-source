# RE-001: map node #115 base/u.rs:531 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/u.rs` as an embedded path. At ELF VA `0x26ffcbc` (file offset `0x26fecbc`), `488d15e578d303` decodes as `lea rdx, [rip + 0x3d378e5]`. Adding the signed displacement `64190693` to the next instruction VA `0x26ffcc3` yields `0x64375a8`. The decode from the start of FDE range `[0x26ff830, 0x270000c)` reaches that instruction boundary. The FDE itself is at `0x1132ab4`.

At `0x64375a8` (file offset `0x64355a8`), an `R_X86_64_RELATIVE` relocation points to `0x442e9e` in `.rodata`. The next 16 bytes, `0d000000000000001302000009000000`, decode as a little-endian 64-bit length of 13 and two 32-bit values, 531 and 9. The string's normalized suffix matches `base/u.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x26ff891` is `0x26ffc95` and the fallthrough is `0x26ff897`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rax, rax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x26ff88e` | `4885c0` | `test rax, rax` |
| `0x26ff891` | `0f85fe030000` | `jne 0x26ffc95` |
| `0x26ffc95` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x26ffc9a` | `4889542410` | `mov qword ptr [rsp + 0x10], rdx` |
| `0x26ffc9f` | `488d442408` | `lea rax, [rsp + 8]` |
| `0x26ffca4` | `4889442448` | `mov qword ptr [rsp + 0x48], rax` |
| `0x26ffca9` | `488d05a07fdaff` | `lea rax, [rip - 0x258060]` |
| `0x26ffcb0` | `4889442450` | `mov qword ptr [rsp + 0x50], rax` |
| `0x26ffcb5` | `488d3d9bbbd3fd` | `lea rdi, [rip - 0x22c4465]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 64879082 added to `0x26ffcce` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x26ffcc3` | `488d742448` | `lea rsi, [rsp + 0x48]` |
| `0x26ffcc8` | `ff15eaf9dd03` | `call qword ptr [rip + 0x3ddf9ea]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64375a8 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x26ff830 --stop-address=0x26ffcce "$target"
od -An -tx1 -j 105076144 -N 16 "$target"
objdump -s -j .rodata --start-address=0x442e9e --stop-address=0x442eab "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15e678d303`), re-decoding lands at `0x64375a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 531, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
