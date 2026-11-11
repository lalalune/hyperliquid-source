# RE-001: trace node #115 net_utils/channel.rs diagnostic argument to a direct call

- Component allocation: `transport`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `net_utils/channel.rs` as an embedded path. At ELF VA `0x2b1e24b` (file offset `0x2b1d24b`), `488d1586139303` decodes as `lea rdx, [rip + 0x3931386]`. Adding the signed displacement `59970438` to the next instruction VA `0x2b1e252` yields `0x644f5d8`. The decode from the start of FDE range `[0x2b1df60, 0x2b1f5f2)` reaches that instruction boundary. The FDE itself is at `0x117f628`.

At `0x644f5d8` (file offset `0x644d5d8`), an `R_X86_64_RELATIVE` relocation points to `0x435a64` in `.rodata`. The next 16 bytes, `1800000000000000750000001e000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 117 and 30. The string's normalized suffix matches `net_utils/channel.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `rdx`, the SysV x86-64 integer argument register 3. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -39047 added to `0x2b1e257` gives `0x2b149d0`. The target's FDE at `0x117da1c` describes `[0x2b149d0, 0x2b14ce7)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2b1e252` | `e87967ffff` | `call 0x2b149d0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644f5d8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2b1df60 --stop-address=0x2b1e257 "$target"
od -An -tx1 -j 105174496 -N 16 "$target"
objdump -s -j .rodata --start-address=0x435a64 --stop-address=0x435a7c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d1587139303`), re-decoding lands at `0x644f5d9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 117, column 30. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
