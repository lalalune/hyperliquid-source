# RE-001: map node #115 l1/raw_signature_tracker.rs:231 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `l1/raw_signature_tracker.rs` as an embedded path. At ELF VA `0x537b117` (file offset `0x537a117`), `488d35eacd1201` decodes as `lea rsi, [rip + 0x112cdea]`. Adding the signed displacement `18009578` to the next instruction VA `0x537b11e` yields `0x64a7f08`. The decode from the start of FDE range `[0x537aa60, 0x537b867)` reaches that instruction boundary. The FDE itself is at `0x1347a38`.

At `0x64a7f08` (file offset `0x64a5f08`), an `R_X86_64_RELATIVE` relocation points to `0x44e7fd` in `.rodata`. The next 16 bytes, `1f00000000000000e700000009000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 231 and 9. The string's normalized suffix matches `l1/raw_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x537b078` establish a local edge into the argument setup. The taken target is `0x537b0a3` and the fallthrough is `0x537b07a`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `test rcx, rcx`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **true**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x537b075` | `4885c9` | `test rcx, rcx` |
| `0x537b078` | `7429` | `je 0x537b0a3` |
| `0x537b0a3` | `31d2` | `xor edx, edx` |
| `0x537b0a5` | `31c0` | `xor eax, eax` |
| `0x537b0a7` | `31f6` | `xor esi, esi` |
| `0x537b0a9` | `498b4d20` | `mov rcx, qword ptr [r13 + 0x20]` |
| `0x537b0ad` | `488d3c92` | `lea rdi, [rdx + rdx*4]` |
| `0x537b0b1` | `48c1e704` | `shl rdi, 4` |
| `0x537b0b5` | `4801cf` | `add rdi, rcx` |
| `0x537b0b8` | `488d0480` | `lea rax, [rax + rax*4]` |
| `0x537b0bc` | `48c1e004` | `shl rax, 4` |
| `0x537b0c0` | `4801c8` | `add rax, rcx` |
| `0x537b0c3` | `488d14b6` | `lea rdx, [rsi + rsi*4]` |
| `0x537b0c7` | `48c1e204` | `shl rdx, 4` |
| `0x537b0cb` | `4801ca` | `add rdx, rcx` |
| `0x537b0ce` | `41b802000000` | `mov r8d, 2` |
| `0x537b0d4` | `4c89442430` | `mov qword ptr [rsp + 0x30], r8` |
| `0x537b0d9` | `48897c2438` | `mov qword ptr [rsp + 0x38], rdi` |
| `0x537b0de` | `4889442440` | `mov qword ptr [rsp + 0x40], rax` |
| `0x537b0e3` | `48894c2448` | `mov qword ptr [rsp + 0x48], rcx` |
| `0x537b0e8` | `4889542450` | `mov qword ptr [rsp + 0x50], rdx` |
| `0x537b0ed` | `48c744245800000000` | `mov qword ptr [rsp + 0x58], 0` |
| `0x537b0f6` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x537b0fb` | `48894c2468` | `mov qword ptr [rsp + 0x68], rcx` |
| `0x537b100` | `4889742470` | `mov qword ptr [rsp + 0x70], rsi` |
| `0x537b105` | `488d8424ff010000` | `lea rax, [rsp + 0x1ff]` |
| `0x537b10d` | `4889442478` | `mov qword ptr [rsp + 0x78], rax` |
| `0x537b112` | `488d7c2430` | `lea rdi, [rsp + 0x30]` |

## Argument flow

The LEA writes `rsi`, the SysV x86-64 integer argument register 2. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -5482387 added to `0x537b123` gives `0x4e40990`. The target's FDE at `0x1303758` describes `[0x4e40990, 0x4e41504)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x537b11e` | `e86d58acff` | `call 0x4e40990` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64a7f08 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x537aa60 --stop-address=0x537b123 "$target"
od -An -tx1 -j 105537296 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e7fd --stop-address=0x44e81c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35ebcd1201`), re-decoding lands at `0x64a7f09`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 231, column 9. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
