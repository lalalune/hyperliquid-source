# RE-001: map node #115 node/consensus/config.rs:45 conditional call edge

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/consensus/config.rs` as an embedded path. At ELF VA `0x24b7fae` (file offset `0x24b6fae`), `488d154395f703` decodes as `lea rdx, [rip + 0x3f79543]`. Adding the signed displacement `66557251` to the next instruction VA `0x24b7fb5` yields `0x64314f8`. The decode from the start of FDE range `[0x24b7920, 0x24b8a7f)` reaches that instruction boundary. The FDE itself is at `0x1116fd0`.

At `0x64314f8` (file offset `0x642f4f8`), an `R_X86_64_RELATIVE` relocation points to `0x449d7b` in `.rodata`. The next 16 bytes, `1c000000000000002d00000019000000`, decode as a little-endian 64-bit length of 28 and two 32-bit values, 45 and 25. The string's normalized suffix matches `node/consensus/config.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x24b7f48` is `0x24b80cc` and the fallthrough is `0x24b7f4e`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test al, al`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x24b7f46` | `84c0` | `test al, al` |
| `0x24b7f48` | `0f857e010000` | `jne 0x24b80cc` |
| `0x24b7f4e` | `488d057b95f703` | `lea rax, [rip + 0x3f7957b]` |
| `0x24b7f55` | `4889842460030000` | `mov qword ptr [rsp + 0x360], rax` |
| `0x24b7f5d` | `488d05ecfcfeff` | `lea rax, [rip - 0x10314]` |
| `0x24b7f64` | `4889842468030000` | `mov qword ptr [rsp + 0x368], rax` |
| `0x24b7f6c` | `488d8424c0020000` | `lea rax, [rsp + 0x2c0]` |
| `0x24b7f74` | `4889842470030000` | `mov qword ptr [rsp + 0x370], rax` |
| `0x24b7f7c` | `488d05add3fcff` | `lea rax, [rip - 0x32c53]` |
| `0x24b7f83` | `4889842478030000` | `mov qword ptr [rsp + 0x378], rax` |
| `0x24b7f8b` | `488d44240c` | `lea rax, [rsp + 0xc]` |
| `0x24b7f90` | `4889842480030000` | `mov qword ptr [rsp + 0x380], rax` |
| `0x24b7f98` | `488d05e10a0000` | `lea rax, [rip + 0xae1]` |
| `0x24b7f9f` | `4889842488030000` | `mov qword ptr [rsp + 0x388], rax` |
| `0x24b7fa7` | `488d3d304ff8fd` | `lea rdi, [rip - 0x207b0d0]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 67270389 added to `0x24b7fc3` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x24b7fb5` | `488db42460030000` | `lea rsi, [rsp + 0x360]` |
| `0x24b7fbd` | `ff15f5760204` | `call qword ptr [rip + 0x40276f5]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64314f8 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x24b7920 --stop-address=0x24b7fc3 "$target"
od -An -tx1 -j 105051392 -N 16 "$target"
objdump -s -j .rodata --start-address=0x449d7b --stop-address=0x449d97 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d154495f703`), re-decoding lands at `0x64314f9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 45, column 25. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
