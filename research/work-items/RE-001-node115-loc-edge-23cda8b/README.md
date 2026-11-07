# RE-001: map node #115 l1/slab/slab.rs:78 conditional call edge

- Component allocation: `orderbook`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/slab/slab.rs` as an embedded path. At ELF VA `0x23cda8b` (file offset `0x23cca8b`), `488d158e1f0604` decodes as `lea rdx, [rip + 0x4061f8e]`. Adding the signed displacement `67510158` to the next instruction VA `0x23cda92` yields `0x642fa20`. The decode from the start of FDE range `[0x23cd700, 0x23cdb25)` reaches that instruction boundary. The FDE itself is at `0x11075c8`.

At `0x642fa20` (file offset `0x642da20`), an `R_X86_64_RELATIVE` relocation points to `0x435923` in `.rodata`. The next 16 bytes, `13000000000000004e00000015000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 78 and 21. The string's normalized suffix matches `l1/slab/slab.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x23cd9bd` is `0x23cda6e` and the fallthrough is `0x23cd9c3`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp dword ptr [rdi + rax], 2`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x23cd9b9` | `833c0702` | `cmp dword ptr [rdi + rax], 2` |
| `0x23cd9bd` | `0f85ab000000` | `jne 0x23cda6e` |
| `0x23cda6e` | `488d442438` | `lea rax, [rsp + 0x38]` |
| `0x23cda73` | `4889442440` | `mov qword ptr [rsp + 0x40], rax` |
| `0x23cda78` | `488b05491c1104` | `mov rax, qword ptr [rip + 0x4111c49]` |
| `0x23cda7f` | `4889442448` | `mov qword ptr [rsp + 0x48], rax` |
| `0x23cda84` | `488d3d275f06fe` | `lea rdi, [rip - 0x1f9a0d9]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 68230171 added to `0x23cda9d` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x23cda92` | `488d742440` | `lea rsi, [rsp + 0x40]` |
| `0x23cda97` | `ff151b1c1104` | `call qword ptr [rip + 0x4111c1b]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*642fa20 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x23cd700 --stop-address=0x23cda9d "$target"
od -An -tx1 -j 105044520 -N 16 "$target"
objdump -s -j .rodata --start-address=0x435923 --stop-address=0x435936 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d158f1f0604`), re-decoding lands at `0x642fa21`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 78, column 21. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
