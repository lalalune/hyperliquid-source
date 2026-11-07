# RE-001: map node #115 l1/bole/user_state.rs:239 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/bole/user_state.rs` as an embedded path. At ELF VA `0x5491756` (file offset `0x5490756`), `488d154b8b0101` decodes as `lea rdx, [rip + 0x1018b4b]`. Adding the signed displacement `16878411` to the next instruction VA `0x549175d` yields `0x64aa2a8`. The decode from the start of FDE range `[0x5491190, 0x5492434)` reaches that instruction boundary. The FDE itself is at `0x135336c`.

At `0x64aa2a8` (file offset `0x64a82a8`), an `R_X86_64_RELATIVE` relocation points to `0x44f5fb` in `.rodata`. The next 16 bytes, `1900000000000000ef0000002c000000`, decode as a little-endian 64-bit length of 25 and two 32-bit values, 239 and 44. The string's normalized suffix matches `l1/bole/user_state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x5491723` is `0x549178d` and the fallthrough is `0x5491725`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp rdx, qword ptr [rbp + 0x18]`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x549171f` | `483b5518` | `cmp rdx, qword ptr [rbp + 0x18]` |
| `0x5491723` | `7368` | `jae 0x549178d` |
| `0x5491725` | `48035510` | `add rdx, qword ptr [rbp + 0x10]` |
| `0x5491729` | `4839da` | `cmp rdx, rbx` |
| `0x549172c` | `b800000000` | `mov eax, 0` |
| `0x5491731` | `480f43c3` | `cmovae rax, rbx` |
| `0x5491735` | `4829c2` | `sub rdx, rax` |
| `0x5491738` | `488b4508` | `mov rax, qword ptr [rbp + 8]` |
| `0x549173c` | `4869cab8000000` | `imul rcx, rdx, 0xb8` |
| `0x5491743` | `488d1c08` | `lea rbx, [rax + rcx]` |
| `0x5491747` | `4883c308` | `add rbx, 8` |
| `0x549174b` | `488dbc24c0000000` | `lea rdi, [rsp + 0xc0]` |
| `0x5491753` | `4889de` | `mov rsi, rbx` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 17129677 added to `0x5491763` gives the relocation slot `0x64e7830`. Its symbol-zero RELATIVE addend is `0x36a0040`. The target's FDE at `0xe00cc4` describes `[0x36a0040, 0x36a01f9)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x549175d` | `ff15cd600501` | `call qword ptr [rip + 0x10560cd]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa2a8 '
readelf -rW "$target" | grep -i '0*64e7830 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5491190 --stop-address=0x5491763 "$target"
od -An -tx1 -j 105546416 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44f5fb --stop-address=0x44f614 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d154c8b0101`), re-decoding lands at `0x64aa2a9`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 239, column 44. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
