# RE-001: map node #115 node/hl_node.rs:375 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/hl_node.rs` as an embedded path. At ELF VA `0x2ae7019` (file offset `0x2ae6019`), `4c8d05100e9603` decodes as `lea r8, [rip + 0x3960e10]`. Adding the signed displacement `60165648` to the next instruction VA `0x2ae7020` yields `0x6447e30`. The decode from the start of FDE range `[0x2ae6d70, 0x2ae7fc4)` reaches that instruction boundary. The FDE itself is at `0x117c4f0`.

At `0x6447e30` (file offset `0x6445e30`), an `R_X86_64_RELATIVE` relocation points to `0x436a23` in `.rodata`. The next 16 bytes, `13000000000000007701000018000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 375 and 24. The string's normalized suffix matches `node/hl_node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2ae6fa5` establish a local edge into the argument setup. The taken target is `0x2ae7531` and the fallthrough is `0x2ae6fab`. The **fallthrough** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `cmp qword ptr [rsp + 0x50], r13`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **false**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ae6fa0` | `4c396c2450` | `cmp qword ptr [rsp + 0x50], r13` |
| `0x2ae6fa5` | `0f8486050000` | `je 0x2ae7531` |
| `0x2ae6fab` | `488b8424b0000000` | `mov rax, qword ptr [rsp + 0xb0]` |
| `0x2ae6fb3` | `4889842420010000` | `mov qword ptr [rsp + 0x120], rax` |
| `0x2ae6fbb` | `0f108424a0000000` | `movups xmm0, xmmword ptr [rsp + 0xa0]` |
| `0x2ae6fc3` | `0f29842410010000` | `movaps xmmword ptr [rsp + 0x110], xmm0` |
| `0x2ae6fcb` | `0f10842490000000` | `movups xmm0, xmmword ptr [rsp + 0x90]` |
| `0x2ae6fd3` | `0f29842400010000` | `movaps xmmword ptr [rsp + 0x100], xmm0` |
| `0x2ae6fdb` | `0f10442450` | `movups xmm0, xmmword ptr [rsp + 0x50]` |
| `0x2ae6fe0` | `0f104c2460` | `movups xmm1, xmmword ptr [rsp + 0x60]` |
| `0x2ae6fe5` | `0f10542470` | `movups xmm2, xmmword ptr [rsp + 0x70]` |
| `0x2ae6fea` | `0f109c2480000000` | `movups xmm3, xmmword ptr [rsp + 0x80]` |
| `0x2ae6ff2` | `0f299c24f0000000` | `movaps xmmword ptr [rsp + 0xf0], xmm3` |
| `0x2ae6ffa` | `0f299424e0000000` | `movaps xmmword ptr [rsp + 0xe0], xmm2` |
| `0x2ae7002` | `0f298c24d0000000` | `movaps xmmword ptr [rsp + 0xd0], xmm1` |
| `0x2ae700a` | `0f298424c0000000` | `movaps xmmword ptr [rsp + 0xc0], xmm0` |
| `0x2ae7012` | `488d151fedb1fd` | `lea rdx, [rip - 0x24e12e1]` |

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -6174197 added to `0x2ae7035` gives `0x2503a40`. The target's FDE at `0x111cf74` describes `[0x2503a40, 0x250400e)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ae7020` | `488db424c0000000` | `lea rsi, [rsp + 0xc0]` |
| `0x2ae7028` | `b91f000000` | `mov ecx, 0x1f` |
| `0x2ae702d` | `4889df` | `mov rdi, rbx` |
| `0x2ae7030` | `e80bcaa1ff` | `call 0x2503a40` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6447e30 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2ae6d70 --stop-address=0x2ae7035 "$target"
od -An -tx1 -j 105143864 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436a23 --stop-address=0x436a36 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05110e9603`), re-decoding lands at `0x6447e31`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 375, column 24. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
