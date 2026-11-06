# RE-001: trace node #115 base/lu.rs diagnostic argument to a direct call

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one source-location record and the straight-line argument flow from its address load to a direct call.

## Observation

The component catalogue lists `base/lu.rs` as an embedded path. At ELF VA `0x158547b` (file offset `0x158447b`), `4c8d0df69be704` decodes as `lea r9, [rip + 0x4e79bf6]`. Adding the signed displacement `82287606` to the next instruction VA `0x1585482` yields `0x63ff078`. The decode from the start of FDE range `[0x1585050, 0x1585988)` reaches that instruction boundary. The FDE itself is at `0x10530ac`.

At `0x63ff078` (file offset `0x63fd078`), an `R_X86_64_RELATIVE` relocation points to `0x4326c1` in `.rodata`. The next 16 bytes, `0e00000000000000230000000f000000`, decode as a little-endian 64-bit length of 14 and two 32-bit values, 35 and 15. The string's normalized suffix matches `base/lu.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Argument flow

The LEA writes `r9`, the SysV x86-64 integer argument register 6. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 177577 added to `0x1585497` gives `0x15b0a40`. The target's FDE at `0x105728c` describes `[0x15b0a40, 0x15b0bea)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1585482` | `488d7c2430` | `lea rdi, [rsp + 0x30]` |
| `0x1585487` | `4889c6` | `mov rsi, rax` |
| `0x158548a` | `4c89f1` | `mov rcx, r14` |
| `0x158548d` | `4c8b442420` | `mov r8, qword ptr [rsp + 0x20]` |
| `0x1585492` | `e8a9b50200` | `call 0x15b0a40` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63ff078 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1585050 --stop-address=0x1585497 "$target"
od -An -tx1 -j 104845440 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4326c1 --stop-address=0x4326cf "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0df79be704`), re-decoding lands at `0x63ff079`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 35, column 15. The observation establishes the value in an incoming register along this instruction path. The caller's identity, reachability and the callee's use of the register remain unresolved. Next, check whether the callee dereferences the register or forwards it. No captured code was executed and no reconstruction gate or byte denominator is claimed.
