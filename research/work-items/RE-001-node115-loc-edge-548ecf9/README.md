# RE-001: map node #115 l1/bole/user_state.rs:239 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/bole/user_state.rs` as an embedded path. At ELF VA `0x548ecf9` (file offset `0x548dcf9`), `488d15a8b50101` decodes as `lea rdx, [rip + 0x101b5a8]`. Adding the signed displacement `16889256` to the next instruction VA `0x548ed00` yields `0x64aa2a8`. The decode from the start of FDE range `[0x548ebd0, 0x548f424)` reaches that instruction boundary. The FDE itself is at `0x1353250`.

At `0x64aa2a8` (file offset `0x64a82a8`), an `R_X86_64_RELATIVE` relocation points to `0x44f5fb` in `.rodata`. The next 16 bytes, `1900000000000000ef0000002c000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 239 and 44. The string's normalized suffix matches `l1/bole/user_state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x548ecc5` is `0x548ed1b` and the fallthrough is `0x548ecc7`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rdx, qword ptr [r12 + 0x18]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x548ecc0` | `493b542418` | `cmp rdx, qword ptr [r12 + 0x18]` |
| `0x548ecc5` | `7354` | `jae 0x548ed1b` |
| `0x548ecc7` | `4c897c2410` | `mov qword ptr [rsp + 0x10], r15` |
| `0x548eccc` | `4989ef` | `mov r15, rbp` |
| `0x548eccf` | `4903542410` | `add rdx, qword ptr [r12 + 0x10]` |
| `0x548ecd4` | `31c0` | `xor eax, eax` |
| `0x548ecd6` | `4c39ea` | `cmp rdx, r13` |
| `0x548ecd9` | `490f43c5` | `cmovae rax, r13` |
| `0x548ecdd` | `4829c2` | `sub rdx, rax` |
| `0x548ece0` | `4c89642428` | `mov qword ptr [rsp + 0x28], r12` |
| `0x548ece5` | `498b442408` | `mov rax, qword ptr [r12 + 8]` |
| `0x548ecea` | `4869cab8000000` | `imul rcx, rdx, 0xb8` |
| `0x548ecf1` | `488d2c08` | `lea rbp, [rax + rcx]` |
| `0x548ecf5` | `4883c508` | `add rbp, 8` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 17140511 added to `0x548ed11` gives the relocation slot `0x64e7830`. Its symbol-zero RELATIVE addend is `0x36a0040`. The target's FDE at `0xe00cc4` describes `[0x36a0040, 0x36a01f9)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x548ed00` | `488dbc2490000000` | `lea rdi, [rsp + 0x90]` |
| `0x548ed08` | `4889ee` | `mov rsi, rbp` |
| `0x548ed0b` | `ff151f8b0501` | `call qword ptr [rip + 0x1058b1f]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa2a8 '
readelf -rW "$target" | grep -i '0*64e7830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x548ebd0 --stop-address=0x548ed11 "$target"
od -An -tx1 -j 105546416 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44f5fb --stop-address=0x44f614 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15a9b50101`), re-decoding lands at `0x64aa2a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 239, column 44. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
