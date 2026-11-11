# RE-001: trace node #115 l1/abci/hash_signature_tracker.rs diagnostic argument to a direct call

- Component allocation: `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `l1/abci/hash_signature_tracker.rs` as an embedded path. At ELF VA `0x5afa4c4` (file offset `0x5af94c4`), `4c8d0565239c00` decodes as `lea r8, [rip + 0x9c2365]`. Adding the signed displacement `10232677` to the next instruction VA `0x5afa4cb` yields `0x64bc830`. The decode from the start of FDE range `[0x5afa3b0, 0x5afa5cf)` reaches that instruction boundary. The FDE itself is at `0x13b28f0`.

At `0x64bc830` (file offset `0x64ba830`), an `R_X86_64_RELATIVE` relocation points to `0x44d8e1` in `.rodata`. The next 16 bytes, `2500000000000000ae0000002a000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 174 and 42. The string's normalized suffix matches `l1/abci/hash_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -13878000 added to `0x5afa4d0` gives `0x4dbe1e0`. The target's FDE at `0x12f8030` describes `[0x4dbe1e0, 0x4dbe6ad)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5afa4cb` | `e8103d2cff` | `call 0x4dbe1e0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64bc830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5afa3b0 --stop-address=0x5afa4d0 "$target"
od -An -tx1 -j 105621560 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44d8e1 --stop-address=0x44d906 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0566239c00`), re-decoding lands at `0x64bc831`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 174, column 42. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
