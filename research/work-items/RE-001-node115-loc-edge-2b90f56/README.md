# RE-001: map node #115 net_utils/async_sleep_retry.rs:32 conditional call edge

- Component allocation: `transport`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `net_utils/async_sleep_retry.rs` as an embedded path. At ELF VA `0x2b90f56` (file offset `0x2b8ff56`), `4c8d058be58b03` decodes as `lea r8, [rip + 0x38be58b]`. Adding the signed displacement `59499915` to the next instruction VA `0x2b90f5d` yields `0x644f4e8`. The decode from the start of FDE range `[0x2b905a0, 0x2b91042)` reaches that instruction boundary. The FDE itself is at `0x1186504`.

At `0x644f4e8` (file offset `0x644d4e8`), an `R_X86_64_RELATIVE` relocation points to `0x436a80` in `.rodata`. The next 16 bytes, `22000000000000002000000026000000`, decode as a little-endian 64-bit length of 34 and two 32-bit values, 32 and 38. The string's normalized suffix matches `net_utils/async_sleep_retry.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2b90efb` is `0x2b90f43` and the fallthrough is `0x2b90efd`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp ebp, 2`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2b90ef8` | `83fd02` | `cmp ebp, 2` |
| `0x2b90efb` | `7446` | `je 0x2b90f43` |
| `0x2b90f43` | `4c89742420` | `mov qword ptr [rsp + 0x20], r14` |
| `0x2b90f48` | `488d3dabdca7fd` | `lea rdi, [rip - 0x2582355]` |
| `0x2b90f4f` | `488d0d82cd8b03` | `lea rcx, [rip + 0x38bcd82]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 60090163 added to `0x2b90f6d` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2b90f5d` | `488d542420` | `lea rdx, [rsp + 0x20]` |
| `0x2b90f62` | `be2b000000` | `mov esi, 0x2b` |
| `0x2b90f67` | `ff1533e79403` | `call qword ptr [rip + 0x394e733]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644f4e8 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2b905a0 --stop-address=0x2b90f6d "$target"
od -An -tx1 -j 105174256 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436a80 --stop-address=0x436aa2 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d058ce58b03`), re-decoding lands at `0x644f4e9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 32, column 38. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
