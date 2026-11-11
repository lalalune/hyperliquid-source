# RE-001: map node #115 base/singleton_set.rs:34 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/singleton_set.rs` as an embedded path. At ELF VA `0x1560d86` (file offset `0x155fd86`), `488d1593d6e904` decodes as `lea rdx, [rip + 0x4e9d693]`. Adding the signed displacement `82433683` to the next instruction VA `0x1560d8d` yields `0x63fe420`. The decode from the start of FDE range `[0x1560ab0, 0x1560e2f)` reaches that instruction boundary. The FDE itself is at `0x10510e8`.

At `0x63fe420` (file offset `0x63fc420`), an `R_X86_64_RELATIVE` relocation points to `0x440ef8` in `.rodata`. The next 16 bytes, `1900000000000000220000000d000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 34 and 13. The string's normalized suffix matches `base/singleton_set.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x1560d5d` is `0x1560da8` and the fallthrough is `0x1560d5f`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `test al, al`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1560d5b` | `84c0` | `test al, al` |
| `0x1560d5d` | `7449` | `je 0x1560da8` |
| `0x1560d5f` | `488d442428` | `lea rax, [rsp + 0x28]` |
| `0x1560d64` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x1560d69` | `4c897c2410` | `mov qword ptr [rsp + 0x10], r15` |
| `0x1560d6e` | `4c89742418` | `mov qword ptr [rsp + 0x18], r14` |
| `0x1560d73` | `488d0566b9ffff` | `lea rax, [rip - 0x469a]` |
| `0x1560d7a` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |
| `0x1560d7f` | `488d3d3d08edfe` | `lea rdi, [rip - 0x112f7c3]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 83355936 added to `0x1560d98` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1560d8d` | `488d742408` | `lea rsi, [rsp + 8]` |
| `0x1560d92` | `ff1520e9f704` | `call qword ptr [rip + 0x4f7e920]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fe420 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1560ab0 --stop-address=0x1560d98 "$target"
od -An -tx1 -j 104842280 -N 16 "$target"
objdump -s -j .rodata --start-address=0x440ef8 --stop-address=0x440f11 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d1594d6e904`), re-decoding lands at `0x63fe421`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 34, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
