# RE-001: map node #115 node/gossip_config.rs:387 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/gossip_config.rs` as an embedded path. At ELF VA `0x2ad8b8e` (file offset `0x2ad7b8e`), `4c8d0d0bee9603` decodes as `lea r9, [rip + 0x396ee0b]`. Adding the signed displacement `60222987` to the next instruction VA `0x2ad8b95` yields `0x64479a0`. The decode from the start of FDE range `[0x2ad7140, 0x2adce3a)` reaches that instruction boundary. The FDE itself is at `0x117c1fc`.

At `0x64479a0` (file offset `0x64459a0`), an `R_X86_64_RELATIVE` relocation points to `0x449029` in `.rodata`. The next 16 bytes, `1900000000000000830100001b000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 387 and 27. The string's normalized suffix matches `node/gossip_config.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x2ad8a2f` establish a local edge into the argument setup. The taken target is `0x2ad8aa8` and the fallthrough is `0x2ad8a31`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `cmp qword ptr [rbx + 0x4a0], 0`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **true**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ad8a27` | `4883bba004000000` | `cmp qword ptr [rbx + 0x4a0], 0` |
| `0x2ad8a2f` | `7477` | `je 0x2ad8aa8` |
| `0x2ad8aa8` | `48c784249000000000000000` | `mov qword ptr [rsp + 0x90], 0` |
| `0x2ad8ab4` | `48c78424a000000000000000` | `mov qword ptr [rsp + 0xa0], 0` |
| `0x2ad8ac0` | `488b8424a0000000` | `mov rax, qword ptr [rsp + 0xa0]` |
| `0x2ad8ac8` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x2ad8acd` | `488b842490000000` | `mov rax, qword ptr [rsp + 0x90]` |
| `0x2ad8ad5` | `4889442450` | `mov qword ptr [rsp + 0x50], rax` |
| `0x2ad8ada` | `488b842498000000` | `mov rax, qword ptr [rsp + 0x98]` |
| `0x2ad8ae2` | `4889442458` | `mov qword ptr [rsp + 0x58], rax` |
| `0x2ad8ae7` | `48b80000000000000080` | `movabs rax, 0x8000000000000000` |
| `0x2ad8af1` | `0f1083a8040000` | `movups xmm0, xmmword ptr [rbx + 0x4a8]` |
| `0x2ad8af8` | `0f108bb8040000` | `movups xmm1, xmmword ptr [rbx + 0x4b8]` |
| `0x2ad8aff` | `0f298c24a0030000` | `movaps xmmword ptr [rsp + 0x3a0], xmm1` |
| `0x2ad8b07` | `0f29842490030000` | `movaps xmmword ptr [rsp + 0x390], xmm0` |
| `0x2ad8b0f` | `f30f6f442470` | `movdqu xmm0, xmmword ptr [rsp + 0x70]` |
| `0x2ad8b15` | `f30f6f8c2480000000` | `movdqu xmm1, xmmword ptr [rsp + 0x80]` |
| `0x2ad8b1e` | `660f7f842450030000` | `movdqa xmmword ptr [rsp + 0x350], xmm0` |
| `0x2ad8b27` | `660f7f8c2460030000` | `movdqa xmmword ptr [rsp + 0x360], xmm1` |
| `0x2ad8b30` | `4889842470030000` | `mov qword ptr [rsp + 0x370], rax` |
| `0x2ad8b38` | `488b442450` | `mov rax, qword ptr [rsp + 0x50]` |
| `0x2ad8b3d` | `4889842478030000` | `mov qword ptr [rsp + 0x378], rax` |
| `0x2ad8b45` | `488b442458` | `mov rax, qword ptr [rsp + 0x58]` |
| `0x2ad8b4a` | `4889842480030000` | `mov qword ptr [rsp + 0x380], rax` |
| `0x2ad8b52` | `488b442460` | `mov rax, qword ptr [rsp + 0x60]` |
| `0x2ad8b57` | `4889842488030000` | `mov qword ptr [rsp + 0x388], rax` |
| `0x2ad8b5f` | `488d05c30497fd` | `lea rax, [rip - 0x268fb3d]` |
| `0x2ad8b66` | `4889442470` | `mov qword ptr [rsp + 0x70], rax` |
| `0x2ad8b6b` | `48c744247819000000` | `mov qword ptr [rsp + 0x78], 0x19` |
| `0x2ad8b74` | `c784248000000083010000` | `mov dword ptr [rsp + 0x80], 0x183` |
| `0x2ad8b7f` | `488b9424c0010000` | `mov rdx, qword ptr [rsp + 0x1c0]` |
| `0x2ad8b87` | `488db230010000` | `lea rsi, [rdx + 0x130]` |

## Argument flow

The LEA writes `r9`, the SysV x86-64 integer argument register 6. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -1080794 added to `0x2ad8baa` gives `0x29d0dd0`. The target's FDE at `0x1162568` describes `[0x29d0dd0, 0x29d179d)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ad8b95` | `488dbc2490000000` | `lea rdi, [rsp + 0x90]` |
| `0x2ad8b9d` | `488d4c2470` | `lea rcx, [rsp + 0x70]` |
| `0x2ad8ba2` | `4531c0` | `xor r8d, r8d` |
| `0x2ad8ba5` | `e82682efff` | `call 0x29d0dd0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64479a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2ad7140 --stop-address=0x2ad8baa "$target"
od -An -tx1 -j 105142696 -N 16 "$target"
objdump -s -j .rodata --start-address=0x449029 --stop-address=0x449042 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d0d0cee9603`), re-decoding lands at `0x64479a1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 387, column 27. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
