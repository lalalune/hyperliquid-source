# RE-001: trace node #115 l1/spot_clearinghouse/cl_trait.rs diagnostic argument to a direct call

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `l1/spot_clearinghouse/cl_trait.rs` as an embedded path. At ELF VA `0x22e79b6` (file offset `0x22e69b6`), `4c8d0583581404` decodes as `lea r8, [rip + 0x4145883]`. Adding the signed displacement `68442243` to the next instruction VA `0x22e79bd` yields `0x642d240`. The decode from the start of FDE range `[0x22e7620, 0x22e7ace)` reaches that instruction boundary. The FDE itself is at `0x10ef508`.

At `0x642d240` (file offset `0x642b240`), an `R_X86_64_RELATIVE` relocation points to `0x449d41` in `.rodata`. The next 16 bytes, `25000000000000007202000029000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 626 and 41. The string's normalized suffix matches `l1/spot_clearinghouse/cl_trait.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 10015371 added to `0x22e79d5` gives `0x2c74c60`. The target's FDE at `0x118e034` describes `[0x2c74c60, 0x2c74e3c)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x22e79bd` | `488d7c2420` | `lea rdi, [rsp + 0x20]` |
| `0x22e79c2` | `488d942400010000` | `lea rdx, [rsp + 0x100]` |
| `0x22e79ca` | `4c89f6` | `mov rsi, r14` |
| `0x22e79cd` | `4c89e1` | `mov rcx, r12` |
| `0x22e79d0` | `e88bd29800` | `call 0x2c74c60` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*642d240 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x22e7620 --stop-address=0x22e79d5 "$target"
od -An -tx1 -j 105034312 -N 16 "$target"
objdump -s -j .rodata --start-address=0x449d41 --stop-address=0x449d66 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0584581404`), re-decoding lands at `0x642d241`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 626, column 41. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
