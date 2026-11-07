# RE-001: map node #115 l1/raw_signature_tracker.rs:231 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional control-flow edge, its source-location record, and the direct call reached along that edge.

## Observation

The component catalogue lists `l1/raw_signature_tracker.rs` as an embedded path. At ELF VA `0x368f49e` (file offset `0x368e49e`), `488d359396dd02` decodes as `lea rsi, [rip + 0x2dd9693]`. Adding the signed displacement `48076435` to the next instruction VA `0x368f4a5` yields `0x6468b38`. The decode from the start of FDE range `[0x368eeb0, 0x368fa2f)` reaches that instruction boundary. The FDE itself is at `0x11eedc0`.

At `0x6468b38` (file offset `0x6466b38`), an `R_X86_64_RELATIVE` relocation points to `0x44e7fd` in `.rodata`. The next 16 bytes, `1f00000000000000e700000009000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 231 and 9. The string's normalized suffix matches `l1/raw_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The `je` and conditional jump at `0x368f407` establish a local edge into the argument setup. The taken target is `0x368f432` and the fallthrough is `0x368f409`. The **taken** edge reaches the location load by the consecutive instructions below. The other immediate successor is outside this recorded straight-line path.

The flags come directly from `test rdx, rdx`. The recorded edge reaches the load when the `je` predicate (`ZF = 1`) is **true**. This identifies the machine condition for this predecessor without assigning source-level meaning to its operands.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x368f404` | `4885d2` | `test rdx, rdx` |
| `0x368f407` | `7429` | `je 0x368f432` |
| `0x368f432` | `31c9` | `xor ecx, ecx` |
| `0x368f434` | `31c0` | `xor eax, eax` |
| `0x368f436` | `4531c0` | `xor r8d, r8d` |
| `0x368f439` | `488b7520` | `mov rsi, qword ptr [rbp + 0x20]` |
| `0x368f43d` | `488d0c89` | `lea rcx, [rcx + rcx*4]` |
| `0x368f441` | `488d3cce` | `lea rdi, [rsi + rcx*8]` |
| `0x368f445` | `488d0480` | `lea rax, [rax + rax*4]` |
| `0x368f449` | `488d0cc6` | `lea rcx, [rsi + rax*8]` |
| `0x368f44d` | `4b8d0480` | `lea rax, [r8 + r8*4]` |
| `0x368f451` | `488d04c6` | `lea rax, [rsi + rax*8]` |
| `0x368f455` | `41b802000000` | `mov r8d, 2` |
| `0x368f45b` | `4c89442410` | `mov qword ptr [rsp + 0x10], r8` |
| `0x368f460` | `48897c2418` | `mov qword ptr [rsp + 0x18], rdi` |
| `0x368f465` | `48894c2420` | `mov qword ptr [rsp + 0x20], rcx` |
| `0x368f46a` | `4889742428` | `mov qword ptr [rsp + 0x28], rsi` |
| `0x368f46f` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x368f474` | `48c744243800000000` | `mov qword ptr [rsp + 0x38], 0` |
| `0x368f47d` | `48894c2440` | `mov qword ptr [rsp + 0x40], rcx` |
| `0x368f482` | `4889742448` | `mov qword ptr [rsp + 0x48], rsi` |
| `0x368f487` | `4889542450` | `mov qword ptr [rsp + 0x50], rdx` |
| `0x368f48c` | `488d84245b010000` | `lea rax, [rsp + 0x15b]` |
| `0x368f494` | `4889442458` | `mov qword ptr [rsp + 0x58], rax` |
| `0x368f499` | `488d7c2410` | `lea rdi, [rsp + 0x10]` |

## Argument flow

The LEA writes `rsi`, the SysV x86-64 integer argument register 2. Along the straight-line path below no intervening instruction writes the register or a subregister. The address therefore arrives in that register on entry to the direct call's target. The signed call displacement 13378982 added to `0x368f4aa` gives `0x4351a50`. The target's FDE at `0xe9e250` describes `[0x4351a50, 0x4351ddd)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x368f4a5` | `e8a625cc00` | `call 0x4351a50` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6468b38 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x368eeb0 --stop-address=0x368f4aa "$target"
od -An -tx1 -j 105278272 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e7fd --stop-address=0x44e81c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d359496dd02`), re-decoding lands at `0x6468b39`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 231, column 9. The observation establishes one local edge and the value in an incoming register on that path. The source-level meaning of the branch operands, runtime reachability and full callee behavior remain unresolved. Next, trace the inputs of the flag-producing instruction back to the caller's state. No captured code was executed and no reconstruction gate or byte denominator is claimed.
