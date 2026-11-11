# RE-001: trace node #115 node/consensus/signature_tracker.rs diagnostic argument to a direct call

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `node/consensus/signature_tracker.rs` as an embedded path. At ELF VA `0x2e0ffd0` (file offset `0x2e0efd0`), `488d3569e46303` decodes as `lea rsi, [rip + 0x363e469]`. Adding the signed displacement `56878185` to the next instruction VA `0x2e0ffd7` yields `0x644e440`. The decode from the start of FDE range `[0x2e098e0, 0x2e11140)` reaches that instruction boundary. The FDE itself is at `0x11b2110`.

At `0x644e440` (file offset `0x644c440`), an `R_X86_64_RELATIVE` relocation points to `0x441468` in `.rodata`. The next 16 bytes, `27000000000000003a00000014000000`, decode as a little-endian 64-bit length of 39 and two 32-bit values, 58 and 20. The string's normalized suffix matches `node/consensus/signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `rsi`, the SysV x86-64 integer argument register 2. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -5653004 added to `0x2e0ffdc` gives `0x28abdd0`. The target's FDE at `0xd66dd8` describes `[0x28abdd0, 0x28abee2)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2e0ffd7` | `e8f4bda9ff` | `call 0x28abdd0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644e440 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2e098e0 --stop-address=0x2e0ffdc "$target"
od -An -tx1 -j 105169992 -N 16 "$target"
objdump -s -j .rodata --start-address=0x441468 --stop-address=0x44148f "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d356ae46303`), re-decoding lands at `0x644e441`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 58, column 20. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
