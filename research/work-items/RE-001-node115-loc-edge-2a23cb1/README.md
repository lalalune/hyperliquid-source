# RE-001: map node #115 evm_rpc/evm_store.rs:452 conditional call edge

- Component allocation: `evm-rpc`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `evm_rpc/evm_store.rs` as an embedded path. At ELF VA `0x2a23cb1` (file offset `0x2a22cb1`), `488d15909fa003` decodes as `lea rdx, [rip + 0x3a09f90]`. Adding the signed displacement `60858256` to the next instruction VA `0x2a23cb8` yields `0x642dc48`. The decode from the start of FDE range `[0x2a238e0, 0x2a2487f)` reaches that instruction boundary. The FDE itself is at `0x116b9a8`.

At `0x642dc48` (file offset `0x642bc48`), an `R_X86_64_RELATIVE` relocation points to `0x44801d` in `.rodata`. The next 16 bytes, `1800000000000000c40100003d000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 452 and 61. The string's normalized suffix matches `evm_rpc/evm_store.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2a23c3d` establish a local edge into the argument setup. The taken target is `0x2a23c63` and the fallthrough is `0x2a23c3f`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `test edx, edx`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **true**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a23c3b` | `85d2` | `test edx, edx` |
| `0x2a23c3d` | `7424` | `je 0x2a23c63` |
| `0x2a23c63` | `0fb793b6000000` | `movzx edx, word ptr [rbx + 0xb6]` |
| `0x2a23c6a` | `66899424a4030000` | `mov word ptr [rsp + 0x3a4], dx` |
| `0x2a23c72` | `8b93b2000000` | `mov edx, dword ptr [rbx + 0xb2]` |
| `0x2a23c78` | `899424a0030000` | `mov dword ptr [rsp + 0x3a0], edx` |
| `0x2a23c7f` | `48898c24a6030000` | `mov qword ptr [rsp + 0x3a6], rcx` |
| `0x2a23c87` | `48898424ae030000` | `mov qword ptr [rsp + 0x3ae], rax` |
| `0x2a23c8f` | `488b83c8000000` | `mov rax, qword ptr [rbx + 0xc8]` |
| `0x2a23c96` | `48898424b6030000` | `mov qword ptr [rsp + 0x3b6], rax` |
| `0x2a23c9e` | `0fb783d0000000` | `movzx eax, word ptr [rbx + 0xd0]` |
| `0x2a23ca5` | `66898424be030000` | `mov word ptr [rsp + 0x3be], ax` |
| `0x2a23cad` | `498d7f28` | `lea rdi, [r15 + 0x28]` |

## Argument flow

The LEA writes `rdx`, the SysV x86-64 integer argument register 3. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -3715493 added to `0x2a23cc5` gives `0x2698b20`. The target's FDE at `0x112bad8` describes `[0x2698b20, 0x2698f31)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2a23cb8` | `488db424a0030000` | `lea rsi, [rsp + 0x3a0]` |
| `0x2a23cc0` | `e85b4ec7ff` | `call 0x2698b20` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*642dc48 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2a238e0 --stop-address=0x2a23cc5 "$target"
od -An -tx1 -j 105036880 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44801d --stop-address=0x448035 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15919fa003`), re-decoding lands at `0x642dc49`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 452, column 61. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
