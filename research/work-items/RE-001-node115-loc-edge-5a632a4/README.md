# RE-001: map node #115 node/connections.rs:167 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `node/connections.rs` as an embedded path. At ELF VA `0x5a632a4` (file offset `0x5a622a4`), `4c8d05b553a500` decodes as `lea r8, [rip + 0xa553b5]`. Adding the signed displacement `10834869` to the next instruction VA `0x5a632ab` yields `0x64b8660`. The decode from the start of FDE range `[0x5a63100, 0x5a6434f)` reaches that instruction boundary. The FDE itself is at `0x13a9c94`.

At `0x64b8660` (file offset `0x64b6660`), an `R_X86_64_RELATIVE` relocation points to `0x445db6` in `.rodata`. The next 16 bytes, `1700000000000000a70000003a000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 167 and 58. The string's normalized suffix matches `node/connections.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `jne` and conditional jump at `0x5a6320e` establish a local edge into the argument setup. The taken target is `0x5a63249` and the fallthrough is `0x5a63210`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `cmp byte ptr [r14 + 0x20], 1`. The recorded edge reaches the load when the `jne` predicate (`ZF = 0`) is **true**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a63209` | `41807e2001` | `cmp byte ptr [r14 + 0x20], 1` |
| `0x5a6320e` | `7539` | `jne 0x5a63249` |
| `0x5a63249` | `31c0` | `xor eax, eax` |
| `0x5a6324b` | `88842418010000` | `mov byte ptr [rsp + 0x118], al` |
| `0x5a63252` | `498b7618` | `mov rsi, qword ptr [r14 + 0x18]` |
| `0x5a63256` | `488d4610` | `lea rax, [rsi + 0x10]` |
| `0x5a6325a` | `488d0def79edfa` | `lea rcx, [rip - 0x5128611]` |
| `0x5a63261` | `48894c2440` | `mov qword ptr [rsp + 0x40], rcx` |
| `0x5a63266` | `48c744244818000000` | `mov qword ptr [rsp + 0x48], 0x18` |
| `0x5a6326f` | `48c744243800000000` | `mov qword ptr [rsp + 0x38], 0` |
| `0x5a63278` | `4881c688000000` | `add rsi, 0x88` |
| `0x5a6327f` | `4889842410020000` | `mov qword ptr [rsp + 0x210], rax` |
| `0x5a63287` | `488d842418010000` | `lea rax, [rsp + 0x118]` |
| `0x5a6328f` | `4889842418020000` | `mov qword ptr [rsp + 0x218], rax` |
| `0x5a63297` | `488d442438` | `lea rax, [rsp + 0x38]` |
| `0x5a6329c` | `4889842420020000` | `mov qword ptr [rsp + 0x220], rax` |

## Argument flow

The LEA writes `r8`, the SysV x86-64 integer argument register 5. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement -11875810 added to `0x5a632c2` gives `0x4f0fce0`. The target's FDE at `0x130a938` describes `[0x4f0fce0, 0x4f1065f)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x5a632ab` | `488dbc2430010000` | `lea rdi, [rsp + 0x130]` |
| `0x5a632b3` | `488d942410020000` | `lea rdx, [rsp + 0x210]` |
| `0x5a632bb` | `31c9` | `xor ecx, ecx` |
| `0x5a632bd` | `e81eca4aff` | `call 0x4f0fce0` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b8660 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5a63100 --stop-address=0x5a632c2 "$target"
od -An -tx1 -j 105604712 -N 16 "$target"
objdump -s -j .rodata --start-address=0x445db6 --stop-address=0x445dcd "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05b653a500`), re-decoding lands at `0x64b8661`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 167, column 58. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
