# RE-001: map node #115 l1/bole/user_state.rs:239 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/bole/user_state.rs` as an embedded path. At ELF VA `0x2bb99d2` (file offset `0x2bb89d2`), `488d15ff3b8903` decodes as `lea rdx, [rip + 0x3893bff]`. Adding the signed displacement `59325439` to the next instruction VA `0x2bb99d9` yields `0x644d5d8`. The decode from the start of FDE range `[0x2bb98a0, 0x2bba0f5)` reaches that instruction boundary. The FDE itself is at `0x1187d2c`.

At `0x644d5d8` (file offset `0x644b5d8`), an `R_X86_64_RELATIVE` relocation points to `0x44f5fb` in `.rodata`. The next 16 bytes, `1900000000000000ef0000002c000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 239 and 44. The string's normalized suffix matches `l1/bole/user_state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2bb99a5` is `0x2bb99f4` and the fallthrough is `0x2bb99a7`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rdx, qword ptr [r13 + 0x18]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2bb99a1` | `493b5518` | `cmp rdx, qword ptr [r13 + 0x18]` |
| `0x2bb99a5` | `734d` | `jae 0x2bb99f4` |
| `0x2bb99a7` | `48896c2410` | `mov qword ptr [rsp + 0x10], rbp` |
| `0x2bb99ac` | `4c89e5` | `mov rbp, r12` |
| `0x2bb99af` | `49035510` | `add rdx, qword ptr [r13 + 0x10]` |
| `0x2bb99b3` | `31c0` | `xor eax, eax` |
| `0x2bb99b5` | `4c39fa` | `cmp rdx, r15` |
| `0x2bb99b8` | `490f43c7` | `cmovae rax, r15` |
| `0x2bb99bc` | `4829c2` | `sub rdx, rax` |
| `0x2bb99bf` | `498b4508` | `mov rax, qword ptr [r13 + 8]` |
| `0x2bb99c3` | `4869cab8000000` | `imul rcx, rdx, 0xb8` |
| `0x2bb99ca` | `4c8d2408` | `lea r12, [rax + rcx]` |
| `0x2bb99ce` | `4983c408` | `add r12, 8` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 59956806 added to `0x2bb99ea` gives the relocation slot `0x64e7830`. Its symbol-zero RELATIVE addend is `0x36a0040`. The target's FDE at `0xe00cc4` describes `[0x36a0040, 0x36a01f9)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2bb99d9` | `488dbc2480000000` | `lea rdi, [rsp + 0x80]` |
| `0x2bb99e1` | `4c89e6` | `mov rsi, r12` |
| `0x2bb99e4` | `ff1546de9203` | `call qword ptr [rip + 0x392de46]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644d5d8 '
readelf -rW "$target" | grep -i '0*64e7830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2bb98a0 --stop-address=0x2bb99ea "$target"
od -An -tx1 -j 105166304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44f5fb --stop-address=0x44f614 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15003c8903`), re-decoding lands at `0x644d5d9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 239, column 44. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
