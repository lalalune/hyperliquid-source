# RE-001: map node #115 l1/simulate_panic.rs:10 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/simulate_panic.rs` as an embedded path. At ELF VA `0x2bdf890` (file offset `0x2bde890`), `488d1559368b03` decodes as `lea rdx, [rip + 0x38b3659]`. Adding the signed displacement `59455065` to the next instruction VA `0x2bdf897` yields `0x6492ef0`. The decode from the start of FDE range `[0x2bdf270, 0x2bdf8ee)` reaches that instruction boundary. The FDE itself is at `0x1188418`.

At `0x6492ef0` (file offset `0x6490ef0`), an `R_X86_64_RELATIVE` relocation points to `0x431bf2` in `.rodata`. The next 16 bytes, `18000000000000000a0000000d000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 10 and 13. The string's normalized suffix matches `l1/simulate_panic.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2bdf33c` is `0x2bdf889` and the fallthrough is `0x2bdf342`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test cl, cl`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2bdf33a` | `84c9` | `test cl, cl` |
| `0x2bdf33c` | `0f8447050000` | `je 0x2bdf889` |
| `0x2bdf889` | `488d3d03bbbffd` | `lea rdi, [rip - 0x24044fd]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 59768462 added to `0x2bdf8a2` gives the relocation slot `0x64df730`. Its symbol-zero RELATIVE addend is `0x1680e60`. The target's FDE at `0xcc30e8` describes `[0x1680e60, 0x1680e72)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2bdf897` | `be0e000000` | `mov esi, 0xe` |
| `0x2bdf89c` | `ff158efe8f03` | `call qword ptr [rip + 0x38ffe8e]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6492ef0 '
readelf -rW "$target" | grep -i '0*64df730 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2bdf270 --stop-address=0x2bdf8a2 "$target"
od -An -tx1 -j 105451256 -N 16 "$target"
objdump -s -j .rodata --start-address=0x431bf2 --stop-address=0x431c0a "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d155a368b03`), re-decoding lands at `0x6492ef1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 10, column 13. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
