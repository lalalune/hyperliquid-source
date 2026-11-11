# RE-001: map node #115 base/production.rs:125 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/production.rs` as an embedded path. At ELF VA `0x15d5b25` (file offset `0x15d4b25`), `488d3d44b7e204` decodes as `lea rdi, [rip + 0x4e2b744]`. Adding the signed displacement `81966916` to the next instruction VA `0x15d5b2c` yields `0x6401270`. The decode from the start of FDE range `[0x15d5b00, 0x15d5cae)` reaches that instruction boundary. The FDE itself is at `0x105b030`.

At `0x6401270` (file offset `0x63ff270`), an `R_X86_64_RELATIVE` relocation points to `0x447b5a` in `.rodata`. The next 16 bytes, `16000000000000007d0000003d000000`, decode as a little-endian 64-bit length of 22 and two 32-bit values, 125 and 61. The string's normalized suffix matches `base/production.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x15d5b1f` is `0x15d5bc1` and the fallthrough is `0x15d5b25`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp eax, 3`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15d5b1c` | `83f803` | `cmp eax, 3` |
| `0x15d5b1f` | `0f849c000000` | `je 0x15d5bc1` |

## Argument flow

The LEA writes `rdi`. The trace follows the unchanged value to the call. At the call, `rdi` is SysV x86-64 integer argument register 1. The signed displacement 82884654 added to `0x15d5b32` gives the relocation slot `0x64e1360`. Its symbol-zero RELATIVE addend is `0x1681e80`. The target's FDE at `0xcc3358` describes `[0x1681e80, 0x1681e99)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x15d5b2c` | `ff152eb8f004` | `call qword ptr [rip + 0x4f0b82e]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6401270 '
readelf -rW "$target" | grep -i '0*64e1360 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x15d5b00 --stop-address=0x15d5b32 "$target"
od -An -tx1 -j 104854136 -N 16 "$target"
objdump -s -j .rodata --start-address=0x447b5a --stop-address=0x447b70 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d45b7e204`), re-decoding lands at `0x6401271`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 125, column 61. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
