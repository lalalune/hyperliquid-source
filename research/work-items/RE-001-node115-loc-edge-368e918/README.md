# RE-001: map node #115 l1/raw_signature_tracker.rs:231 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/raw_signature_tracker.rs` as an embedded path. At ELF VA `0x368e918` (file offset `0x368d918`), `488d3519a2dd02` decodes as `lea rsi, [rip + 0x2dda219]`. Adding the signed displacement `48079385` to the next instruction VA `0x368e91f` yields `0x6468b38`. The decode from the start of FDE range `[0x368e2e0, 0x368eeac)` reaches that instruction boundary. The FDE itself is at `0x11eed6c`.

At `0x6468b38` (file offset `0x6466b38`), an `R_X86_64_RELATIVE` relocation points to `0x44e7fd` in `.rodata`. The next 16 bytes, `1f00000000000000e700000009000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 231 and 9. The string's normalized suffix matches `l1/raw_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x368e873` is `0x368e89e` and the fallthrough is `0x368e875`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rcx, rcx`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x368e870` | `4885c9` | `test rcx, rcx` |
| `0x368e873` | `7429` | `je 0x368e89e` |
| `0x368e89e` | `31d2` | `xor edx, edx` |
| `0x368e8a0` | `31c0` | `xor eax, eax` |
| `0x368e8a2` | `31f6` | `xor esi, esi` |
| `0x368e8a4` | `498b4d20` | `mov rcx, qword ptr [r13 + 0x20]` |
| `0x368e8a8` | `488d3c52` | `lea rdi, [rdx + rdx*2]` |
| `0x368e8ac` | `48c1e704` | `shl rdi, 4` |
| `0x368e8b0` | `4801cf` | `add rdi, rcx` |
| `0x368e8b3` | `488d0440` | `lea rax, [rax + rax*2]` |
| `0x368e8b7` | `48c1e004` | `shl rax, 4` |
| `0x368e8bb` | `4801c8` | `add rax, rcx` |
| `0x368e8be` | `488d1476` | `lea rdx, [rsi + rsi*2]` |
| `0x368e8c2` | `48c1e204` | `shl rdx, 4` |
| `0x368e8c6` | `4801ca` | `add rdx, rcx` |
| `0x368e8c9` | `41b802000000` | `mov r8d, 2` |
| `0x368e8cf` | `4c89442440` | `mov qword ptr [rsp + 0x40], r8` |
| `0x368e8d4` | `48897c2448` | `mov qword ptr [rsp + 0x48], rdi` |
| `0x368e8d9` | `4889442450` | `mov qword ptr [rsp + 0x50], rax` |
| `0x368e8de` | `48894c2458` | `mov qword ptr [rsp + 0x58], rcx` |
| `0x368e8e3` | `4889542460` | `mov qword ptr [rsp + 0x60], rdx` |
| `0x368e8e8` | `48c744246800000000` | `mov qword ptr [rsp + 0x68], 0` |
| `0x368e8f1` | `4889442470` | `mov qword ptr [rsp + 0x70], rax` |
| `0x368e8f6` | `48894c2478` | `mov qword ptr [rsp + 0x78], rcx` |
| `0x368e8fb` | `4889b42480000000` | `mov qword ptr [rsp + 0x80], rsi` |
| `0x368e903` | `488d842460010000` | `lea rax, [rsp + 0x160]` |
| `0x368e90b` | `4889842488000000` | `mov qword ptr [rsp + 0x88], rax` |
| `0x368e913` | `488d7c2440` | `lea rdi, [rsp + 0x40]` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed call displacement 13388140 added to `0x368e924` gives `0x4353290`. The target's FDE at `0xe9e458` describes `[0x4353290, 0x4353609)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x368e91f` | `e86c49cc00` | `call 0x4353290` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6468b38 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x368e2e0 --stop-address=0x368e924 "$target"
od -An -tx1 -j 105278272 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e7fd --stop-address=0x44e81c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d351aa2dd02`), re-decoding lands at `0x6468b39`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 231, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
