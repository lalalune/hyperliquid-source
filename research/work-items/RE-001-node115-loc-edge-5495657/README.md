# RE-001: map node #115 l1/raw_vlm.rs:17 conditional call edge

- Component allocation: `fees`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/raw_vlm.rs` as an embedded path. At ELF VA `0x5495657` (file offset `0x5494657`), `488d3582e9fe00` decodes as `lea rsi, [rip + 0xfee982]`. Adding the signed displacement `16705922` to the next instruction VA `0x549565e` yields `0x6483fe0`. The decode from the start of FDE range `[0x5495210, 0x5495671)` reaches that instruction boundary. The FDE itself is at `0xf83b04`.

At `0x6483fe0` (file offset `0x6481fe0`), an `R_X86_64_RELATIVE` relocation points to `0x43e2d0` in `.rodata`. The next 16 bytes, `11000000000000001100000015000000`, decode as a little-endian 64-bit length of 17 and two 32-bit values, 17 and 21. The string's normalized suffix matches `l1/raw_vlm.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5495526` is `0x5495657` and the fallthrough is `0x549552c`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp r14, rbx`. The recorded edge is selected when the `ja` predicate (`CF = 0 and ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5495523` | `4939de` | `cmp r14, rbx` |
| `0x5495526` | `0f872b010000` | `ja 0x5495657` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 17102911 added to `0x5495669` gives the relocation slot `0x64e4ea8`. Its symbol-zero RELATIVE addend is `0x4524e40`. The target's FDE at `0x12aa518` describes `[0x4524e40, 0x4524fb1)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x549565e` | `31ff` | `xor edi, edi` |
| `0x5495660` | `4889c3` | `mov rbx, rax` |
| `0x5495663` | `ff153ff80401` | `call qword ptr [rip + 0x104f83f]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6483fe0 '
readelf -rW "$target" | grep -i '0*64e4ea8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5495210 --stop-address=0x5495669 "$target"
od -An -tx1 -j 105390056 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43e2d0 --stop-address=0x43e2e1 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3583e9fe00`), re-decoding lands at `0x6483fe1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 17, column 21. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
