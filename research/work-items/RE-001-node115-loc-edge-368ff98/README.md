# RE-001: map node #115 l1/raw_signature_tracker.rs:231 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/raw_signature_tracker.rs` as an embedded path. At ELF VA `0x368ff98` (file offset `0x368ef98`), `488d35998bdd02` decodes as `lea rsi, [rip + 0x2dd8b99]`. Adding the signed displacement `48073625` to the next instruction VA `0x368ff9f` yields `0x6468b38`. The decode from the start of FDE range `[0x368fa30, 0x369057e)` reaches that instruction boundary. The FDE itself is at `0x11eee14`.

At `0x6468b38` (file offset `0x6466b38`), an `R_X86_64_RELATIVE` relocation points to `0x44e7fd` in `.rodata`. The next 16 bytes, `1f00000000000000e700000009000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 231 and 9. The string's normalized suffix matches `l1/raw_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x368ff00` is `0x368ff2b` and the fallthrough is `0x368ff02`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rsi, rsi`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x368fefd` | `4885f6` | `test rsi, rsi` |
| `0x368ff00` | `7429` | `je 0x368ff2b` |
| `0x368ff2b` | `31d2` | `xor edx, edx` |
| `0x368ff2d` | `31c0` | `xor eax, eax` |
| `0x368ff2f` | `31c9` | `xor ecx, ecx` |
| `0x368ff31` | `488b742418` | `mov rsi, qword ptr [rsp + 0x18]` |
| `0x368ff36` | `488b7620` | `mov rsi, qword ptr [rsi + 0x20]` |
| `0x368ff3a` | `48c1e206` | `shl rdx, 6` |
| `0x368ff3e` | `4801f2` | `add rdx, rsi` |
| `0x368ff41` | `48c1e006` | `shl rax, 6` |
| `0x368ff45` | `4801f0` | `add rax, rsi` |
| `0x368ff48` | `48c1e106` | `shl rcx, 6` |
| `0x368ff4c` | `4801f1` | `add rcx, rsi` |
| `0x368ff4f` | `41b802000000` | `mov r8d, 2` |
| `0x368ff55` | `4c89442430` | `mov qword ptr [rsp + 0x30], r8` |
| `0x368ff5a` | `4889542438` | `mov qword ptr [rsp + 0x38], rdx` |
| `0x368ff5f` | `4889442440` | `mov qword ptr [rsp + 0x40], rax` |
| `0x368ff64` | `4889742448` | `mov qword ptr [rsp + 0x48], rsi` |
| `0x368ff69` | `48894c2450` | `mov qword ptr [rsp + 0x50], rcx` |
| `0x368ff6e` | `48c744245800000000` | `mov qword ptr [rsp + 0x58], 0` |
| `0x368ff77` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x368ff7c` | `4889742468` | `mov qword ptr [rsp + 0x68], rsi` |
| `0x368ff81` | `48897c2470` | `mov qword ptr [rsp + 0x70], rdi` |
| `0x368ff86` | `488d8424a0000000` | `lea rax, [rsp + 0xa0]` |
| `0x368ff8e` | `4889442478` | `mov qword ptr [rsp + 0x78], rax` |
| `0x368ff93` | `488d7c2430` | `lea rdi, [rsp + 0x30]` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed call displacement 13383276 added to `0x368ffa4` gives `0x4353610`. The target's FDE at `0xe9e4a8` describes `[0x4353610, 0x4353989)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x368ff9f` | `e86c36cc00` | `call 0x4353610` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6468b38 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x368fa30 --stop-address=0x368ffa4 "$target"
od -An -tx1 -j 105278272 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e7fd --stop-address=0x44e81c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d359a8bdd02`), re-decoding lands at `0x6468b39`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 231, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
