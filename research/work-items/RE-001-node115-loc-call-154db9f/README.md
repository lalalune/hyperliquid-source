# RE-001: trace node #115 base/cid.rs diagnostic argument to a direct call

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `base/cid.rs` as an embedded path. At ELF VA `0x154db9f` (file offset `0x154cb9f`), `488d0d5201eb04` decodes as `lea rcx, [rip + 0x4eb0152]`. Adding the signed displacement `82510162` to the next instruction VA `0x154dba6` yields `0x63fdcf8`. The decode from the start of FDE range `[0x154d390, 0x154e96a)` reaches that instruction boundary. The FDE itself is at `0x10502f0`.

At `0x63fdcf8` (file offset `0x63fbcf8`), an `R_X86_64_RELATIVE` relocation points to `0x44d4c1` in `.rodata`. The next 16 bytes, `0f000000000000002700000039000000`, decode as a little-endian 64-bit length of 15 and two 32-bit values, 39 and 57. The string's normalized suffix matches `base/cid.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `rcx`, the SysV x86-64 integer argument register 4. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -305275 added to `0x154dbab` gives `0x1503330`. The target's FDE at `0x104b2c8` describes `[0x1503330, 0x150366e)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x154dba6` | `e88557fbff` | `call 0x1503330` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fdcf8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x154d390 --stop-address=0x154dbab "$target"
od -An -tx1 -j 104840448 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44d4c1 --stop-address=0x44d4d0 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0d5301eb04`), re-decoding lands at `0x63fdcf9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 39, column 57. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
