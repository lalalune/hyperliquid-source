# RE-001: map node #115 l1/bole/user_state.rs:239 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/bole/user_state.rs` as an embedded path. At ELF VA `0x2c63d7e` (file offset `0x2c62d7e`), `488d1553987e03` decodes as `lea rdx, [rip + 0x37e9853]`. Adding the signed displacement `58628179` to the next instruction VA `0x2c63d85` yields `0x644d5d8`. The decode from the start of FDE range `[0x2c62820, 0x2c64862)` reaches that instruction boundary. The FDE itself is at `0x118d658`.

At `0x644d5d8` (file offset `0x644b5d8`), an `R_X86_64_RELATIVE` relocation points to `0x44f5fb` in `.rodata`. The next 16 bytes, `1900000000000000ef0000002c000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 239 and 44. The string's normalized suffix matches `l1/bole/user_state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2c63d47` is `0x2c63e04` and the fallthrough is `0x2c63d4d`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rdx, qword ptr [rbx + 0x18]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c63d43` | `483b5318` | `cmp rdx, qword ptr [rbx + 0x18]` |
| `0x2c63d47` | `0f83b7000000` | `jae 0x2c63e04` |
| `0x2c63d4d` | `48035310` | `add rdx, qword ptr [rbx + 0x10]` |
| `0x2c63d51` | `4c39f2` | `cmp rdx, r14` |
| `0x2c63d54` | `b800000000` | `mov eax, 0` |
| `0x2c63d59` | `490f43c6` | `cmovae rax, r14` |
| `0x2c63d5d` | `4829c2` | `sub rdx, rax` |
| `0x2c63d60` | `488b4308` | `mov rax, qword ptr [rbx + 8]` |
| `0x2c63d64` | `4869cab8000000` | `imul rcx, rdx, 0xb8` |
| `0x2c63d6b` | `4c8d2408` | `lea r12, [rax + rcx]` |
| `0x2c63d6f` | `4983c408` | `add r12, 8` |
| `0x2c63d73` | `488dbc24a0000000` | `lea rdi, [rsp + 0xa0]` |
| `0x2c63d7b` | `4c89e6` | `mov rsi, r12` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 59259557 added to `0x2c63d8b` gives the relocation slot `0x64e7830`. Its symbol-zero RELATIVE addend is `0x36a0040`. The target's FDE at `0xe00cc4` describes `[0x36a0040, 0x36a01f9)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c63d85` | `ff15a53a8803` | `call qword ptr [rip + 0x3883aa5]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*644d5d8 '
readelf -rW "$target" | grep -i '0*64e7830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2c62820 --stop-address=0x2c63d8b "$target"
od -An -tx1 -j 105166304 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44f5fb --stop-address=0x44f614 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d1554987e03`), re-decoding lands at `0x644d5d9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 239, column 44. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
