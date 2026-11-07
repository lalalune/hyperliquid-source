# RE-001: map node #115 l1/raw_signature_tracker.rs:231 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/raw_signature_tracker.rs` as an embedded path. At ELF VA `0x368cc50` (file offset `0x368bc50`), `488d35e1bedd02` decodes as `lea rsi, [rip + 0x2ddbee1]`. Adding the signed displacement `48086753` to the next instruction VA `0x368cc57` yields `0x6468b38`. The decode from the start of FDE range `[0x368c5b0, 0x368d379)` reaches that instruction boundary. The FDE itself is at `0x11eecc4`.

At `0x6468b38` (file offset `0x6466b38`), an `R_X86_64_RELATIVE` relocation points to `0x44e7fd` in `.rodata`. The next 16 bytes, `1f00000000000000e700000009000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 231 and 9. The string's normalized suffix matches `l1/raw_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x368cbbd` is `0x368cbe8` and the fallthrough is `0x368cbbf`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rdx, rdx`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x368cbba` | `4885d2` | `test rdx, rdx` |
| `0x368cbbd` | `7429` | `je 0x368cbe8` |
| `0x368cbe8` | `31c9` | `xor ecx, ecx` |
| `0x368cbea` | `31c0` | `xor eax, eax` |
| `0x368cbec` | `31f6` | `xor esi, esi` |
| `0x368cbee` | `498b5020` | `mov rdx, qword ptr [r8 + 0x20]` |
| `0x368cbf2` | `486bf968` | `imul rdi, rcx, 0x68` |
| `0x368cbf6` | `4801d7` | `add rdi, rdx` |
| `0x368cbf9` | `486bc068` | `imul rax, rax, 0x68` |
| `0x368cbfd` | `4801d0` | `add rax, rdx` |
| `0x368cc00` | `486bce68` | `imul rcx, rsi, 0x68` |
| `0x368cc04` | `4801d1` | `add rcx, rdx` |
| `0x368cc07` | `41b802000000` | `mov r8d, 2` |
| `0x368cc0d` | `4c89442430` | `mov qword ptr [rsp + 0x30], r8` |
| `0x368cc12` | `48897c2438` | `mov qword ptr [rsp + 0x38], rdi` |
| `0x368cc17` | `4889442440` | `mov qword ptr [rsp + 0x40], rax` |
| `0x368cc1c` | `4889542448` | `mov qword ptr [rsp + 0x48], rdx` |
| `0x368cc21` | `48894c2450` | `mov qword ptr [rsp + 0x50], rcx` |
| `0x368cc26` | `48c744245800000000` | `mov qword ptr [rsp + 0x58], 0` |
| `0x368cc2f` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x368cc34` | `4889542468` | `mov qword ptr [rsp + 0x68], rdx` |
| `0x368cc39` | `4889742470` | `mov qword ptr [rsp + 0x70], rsi` |
| `0x368cc3e` | `488d8424b0010000` | `lea rax, [rsp + 0x1b0]` |
| `0x368cc46` | `4889442478` | `mov qword ptr [rsp + 0x78], rax` |
| `0x368cc4b` | `488d7c2430` | `lea rdi, [rsp + 0x30]` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed call displacement 13390596 added to `0x368cc5c` gives `0x4351f60`. The target's FDE at `0xe9e2dc` describes `[0x4351f60, 0x43523ce)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x368cc57` | `e80453cc00` | `call 0x4351f60` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6468b38 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x368c5b0 --stop-address=0x368cc5c "$target"
od -An -tx1 -j 105278272 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e7fd --stop-address=0x44e81c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35e2bedd02`), re-decoding lands at `0x6468b39`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 231, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
