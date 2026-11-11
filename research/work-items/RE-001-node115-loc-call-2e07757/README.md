# RE-001: trace node #115 node/channel.rs diagnostic argument to a direct call

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `node/channel.rs` as an embedded path. At ELF VA `0x2e07757` (file offset `0x2e06757`), `488d15b2a36403` decodes as `lea rdx, [rip + 0x364a3b2]`. Adding the signed displacement `56927154` to the next instruction VA `0x2e0775e` yields `0x6451b10`. The decode from the start of FDE range `[0x2e075f0, 0x2e079f6)` reaches that instruction boundary. The FDE itself is at `0x11b1f70`.

At `0x6451b10` (file offset `0x644fb10`), an `R_X86_64_RELATIVE` relocation points to `0x430aa0` in `.rodata`. The next 16 bytes, `13000000000000001400000021000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 20 and 33. The string's normalized suffix matches `node/channel.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `rdx`, the SysV x86-64 integer argument register 3. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -1152598 added to `0x2e07766` gives `0x2cee110`. The target's FDE at `0x1198e2c` describes `[0x2cee110, 0x2cee23e)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2e0775e` | `4c89ff` | `mov rdi, r15` |
| `0x2e07761` | `e8aa69eeff` | `call 0x2cee110` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6451b10 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2e075f0 --stop-address=0x2e07766 "$target"
od -An -tx1 -j 105184024 -N 16 "$target"
objdump -s -j .rodata --start-address=0x430aa0 --stop-address=0x430ab3 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15b3a36403`), re-decoding lands at `0x6451b11`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 20, column 33. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
