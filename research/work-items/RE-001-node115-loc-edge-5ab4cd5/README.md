# RE-001: map node #115 net_utils/tcp/read.rs:35 conditional call edge

- Component allocation: `transport`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `net_utils/tcp/read.rs` as an embedded path. At ELF VA `0x5ab4cd5` (file offset `0x5ab3cd5`), `488d0d3464a000` decodes as `lea rcx, [rip + 0xa06434]`. Adding the signed displacement `10511412` to the next instruction VA `0x5ab4cdc` yields `0x64bb110`. The decode from the start of FDE range `[0x5ab4390, 0x5ab5b4d)` reaches that instruction boundary. The FDE itself is at `0x13ae534`.

At `0x64bb110` (file offset `0x64b9110`), an `R_X86_64_RELATIVE` relocation points to `0x43ada2` in `.rodata`. The next 16 bytes, `1900000000000000230000000d000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 35 and 13. The string's normalized suffix matches `net_utils/tcp/read.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5ab4c02` is `0x5ab4d9d` and the fallthrough is `0x5ab4c08`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp qword ptr [rbx + 0x28], r14`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5ab4bfe` | `4c397328` | `cmp qword ptr [rbx + 0x28], r14` |
| `0x5ab4c02` | `0f8395010000` | `jae 0x5ab4d9d` |
| `0x5ab4c08` | `488d4b58` | `lea rcx, [rbx + 0x58]` |
| `0x5ab4c0c` | `488d5328` | `lea rdx, [rbx + 0x28]` |
| `0x5ab4c10` | `48c784240002000000000000` | `mov qword ptr [rsp + 0x200], 0` |
| `0x5ab4c1c` | `c784241002000000000000` | `mov dword ptr [rsp + 0x210], 0` |
| `0x5ab4c27` | `66c78424140200000000` | `mov word ptr [rsp + 0x214], 0` |
| `0x5ab4c31` | `488d057379e8fa` | `lea rax, [rip - 0x517868d]` |
| `0x5ab4c38` | `4889442450` | `mov qword ptr [rsp + 0x50], rax` |
| `0x5ab4c3d` | `48c744245833000000` | `mov qword ptr [rsp + 0x58], 0x33` |
| `0x5ab4c46` | `488d4330` | `lea rax, [rbx + 0x30]` |
| `0x5ab4c4a` | `4889842498010000` | `mov qword ptr [rsp + 0x198], rax` |
| `0x5ab4c52` | `48894c2438` | `mov qword ptr [rsp + 0x38], rcx` |
| `0x5ab4c57` | `48899424a0010000` | `mov qword ptr [rsp + 0x1a0], rdx` |
| `0x5ab4c5f` | `488d442450` | `lea rax, [rsp + 0x50]` |
| `0x5ab4c64` | `48898424c0000000` | `mov qword ptr [rsp + 0xc0], rax` |
| `0x5ab4c6c` | `4c8d25ad55d7ff` | `lea r12, [rip - 0x28aa53]` |
| `0x5ab4c73` | `4c89a424c8000000` | `mov qword ptr [rsp + 0xc8], r12` |
| `0x5ab4c7b` | `4c8dac2498010000` | `lea r13, [rsp + 0x198]` |
| `0x5ab4c83` | `4c89ac24d0000000` | `mov qword ptr [rsp + 0xd0], r13` |
| `0x5ab4c8b` | `488d050e4fd7ff` | `lea rax, [rip - 0x28b0f2]` |
| `0x5ab4c92` | `48898424d8000000` | `mov qword ptr [rsp + 0xd8], rax` |
| `0x5ab4c9a` | `488d6c2438` | `lea rbp, [rsp + 0x38]` |
| `0x5ab4c9f` | `4889ac24e0000000` | `mov qword ptr [rsp + 0xe0], rbp` |
| `0x5ab4ca7` | `4c8d35f254d7ff` | `lea r14, [rip - 0x28ab0e]` |
| `0x5ab4cae` | `4c89b424e8000000` | `mov qword ptr [rsp + 0xe8], r14` |
| `0x5ab4cb6` | `4c8dbc24a0010000` | `lea r15, [rsp + 0x1a0]` |
| `0x5ab4cbe` | `4c89bc24f0000000` | `mov qword ptr [rsp + 0xf0], r15` |
| `0x5ab4cc6` | `4c89b424f8000000` | `mov qword ptr [rsp + 0xf8], r14` |
| `0x5ab4cce` | `488d35a81199fa` | `lea rsi, [rip - 0x566ee58]` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 10665510 added to `0x5ab4cf2` gives the relocation slot `0x64e0b18`. Its symbol-zero RELATIVE addend is `0x150b310`. The target's FDE at `0x104b978` describes `[0x150b310, 0x150baaf)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5ab4cdc` | `488dbc2400020000` | `lea rdi, [rsp + 0x200]` |
| `0x5ab4ce4` | `488d9424c0000000` | `lea rdx, [rsp + 0xc0]` |
| `0x5ab4cec` | `ff1526bea200` | `call qword ptr [rip + 0xa2be26]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64bb110 '
readelf -rW "$target" | grep -i '0*64e0b18 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5ab4390 --stop-address=0x5ab4cf2 "$target"
od -An -tx1 -j 105615640 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43ada2 --stop-address=0x43adbb "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d3564a000`), re-decoding lands at `0x64bb111`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 35, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
