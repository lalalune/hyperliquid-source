# RE-001: map node #115 node/consensus/server.rs:515 conditional call edge

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/consensus/server.rs` as an embedded path. At ELF VA `0x2afa7c0` (file offset `0x2af97c0`), `488d0dd1e59b03` decodes as `lea rcx, [rip + 0x39be5d1]`. Adding the signed displacement `60548561` to the next instruction VA `0x2afa7c7` yields `0x64b8d98`. The decode from the start of FDE range `[0x2afa140, 0x2afae1e)` reaches that instruction boundary. The FDE itself is at `0x117cbf8`.

At `0x64b8d98` (file offset `0x64b6d98`), an `R_X86_64_RELATIVE` relocation points to `0x432bae` in `.rodata`. The next 16 bytes, `1c00000000000000030200000e000000`, decode as a little-endian 64-bit length of 28 and two 32-bit values, 515 and 14. The string's normalized suffix matches `node/consensus/server.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2afa767` establish a local edge into the argument setup. The taken target is `0x2afa7de` and the fallthrough is `0x2afa769`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `cmp r15d, 0x100007f`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **false**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2afa760` | `4181ff7f000001` | `cmp r15d, 0x100007f` |
| `0x2afa767` | `7475` | `je 0x2afa7de` |
| `0x2afa769` | `488d4710` | `lea rax, [rdi + 0x10]` |
| `0x2afa76d` | `488d0d4d0ee4fd` | `lea rcx, [rip - 0x21bf1b3]` |
| `0x2afa774` | `48898c2430030000` | `mov qword ptr [rsp + 0x330], rcx` |
| `0x2afa77c` | `48c784243803000011000000` | `mov qword ptr [rsp + 0x338], 0x11` |
| `0x2afa788` | `48c784242803000000000000` | `mov qword ptr [rsp + 0x328], 0` |
| `0x2afa794` | `4881c740010000` | `add rdi, 0x140` |
| `0x2afa79b` | `48898424a8000000` | `mov qword ptr [rsp + 0xa8], rax` |
| `0x2afa7a3` | `488d442460` | `lea rax, [rsp + 0x60]` |
| `0x2afa7a8` | `48898424b0000000` | `mov qword ptr [rsp + 0xb0], rax` |
| `0x2afa7b0` | `488d842428030000` | `lea rax, [rsp + 0x328]` |
| `0x2afa7b8` | `48898424b8000000` | `mov qword ptr [rsp + 0xb8], rax` |

## Argument flow

The LEA writes `rcx`, the SysV x86-64 integer argument register 4. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 37828730 added to `0x2afa7d6` gives `0x4f0e050`. The target's FDE at `0x130a7f4` describes `[0x4f0e050, 0x4f0e985)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2afa7c7` | `488db424a8000000` | `lea rsi, [rsp + 0xa8]` |
| `0x2afa7cf` | `31d2` | `xor edx, edx` |
| `0x2afa7d1` | `e87a384102` | `call 0x4f0e050` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b8d98 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2afa140 --stop-address=0x2afa7d6 "$target"
od -An -tx1 -j 105606560 -N 16 "$target"
objdump -s -j .rodata --start-address=0x432bae --stop-address=0x432bca "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0dd2e59b03`), re-decoding lands at `0x64b8d99`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 515, column 14. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
