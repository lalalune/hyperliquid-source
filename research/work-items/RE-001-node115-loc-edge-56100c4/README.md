# RE-001: map node #115 l1/exchange/impl_user.rs:195 conditional call edge

- Component allocation: `exchange`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/exchange/impl_user.rs` as an embedded path. At ELF VA `0x56100c4` (file offset `0x560f0c4`), `488d0db5a5e900` decodes as `lea rcx, [rip + 0xe9a5b5]`. Adding the signed displacement `15312309` to the next instruction VA `0x56100cb` yields `0x64aa680`. The decode from the start of FDE range `[0x560ff80, 0x56104fd)` reaches that instruction boundary. The FDE itself is at `0xf87380`.

At `0x64aa680` (file offset `0x64a8680`), an `R_X86_64_RELATIVE` relocation points to `0x44c976` in `.rodata`. The next 16 bytes, `1c00000000000000c300000028000000`, decode as a little-endian 64-bit length of 28 and two 32-bit values, 195 and 40. The string's normalized suffix matches `l1/exchange/impl_user.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x56100ab` is `0x56100e5` and the fallthrough is `0x56100ad`. The **fallthrough** edge reaches the location load along the instructions below.

The flags come from `cmp eax, 0xffff`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **false**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x56100a6` | `3dffff0000` | `cmp eax, 0xffff` |
| `0x56100ab` | `7438` | `je 0x56100e5` |
| `0x56100ad` | `418b4610` | `mov eax, dword ptr [r14 + 0x10]` |
| `0x56100b1` | `89442460` | `mov dword ptr [rsp + 0x60], eax` |
| `0x56100b5` | `f3410f6f06` | `movdqu xmm0, xmmword ptr [r14]` |
| `0x56100ba` | `660f7f442450` | `movdqa xmmword ptr [rsp + 0x50], xmm0` |
| `0x56100c0` | `400fb6f5` | `movzx esi, bpl` |

## Argument flow

The LEA writes `rcx`. The trace follows the unchanged value to the call. At the call, `rcx` is SysV x86-64 integer argument register 4. The signed displacement 15564327 added to `0x56100d9` gives the relocation slot `0x64e7f00`. Its symbol-zero RELATIVE addend is `0x3c377b0`. The target's FDE at `0xe5302c` describes `[0x3c377b0, 0x3c37ad7)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x56100cb` | `488d542450` | `lea rdx, [rsp + 0x50]` |
| `0x56100d0` | `4c89ff` | `mov rdi, r15` |
| `0x56100d3` | `ff15277eed00` | `call qword ptr [rip + 0xed7e27]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64aa680 '
readelf -rW "$target" | grep -i '0*64e7f00 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x560ff80 --stop-address=0x56100d9 "$target"
od -An -tx1 -j 105547400 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44c976 --stop-address=0x44c992 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0db6a5e900`), re-decoding lands at `0x64aa681`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 195, column 40. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
