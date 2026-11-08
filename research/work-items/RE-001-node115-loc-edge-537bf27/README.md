# RE-001: map node #115 l1/raw_signature_tracker.rs:231 conditional call edge

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/raw_signature_tracker.rs` as an embedded path. At ELF VA `0x537bf27` (file offset `0x537af27`), `488d35dabf1201` decodes as `lea rsi, [rip + 0x112bfda]`. Adding the signed displacement `18005978` to the next instruction VA `0x537bf2e` yields `0x64a7f08`. The decode from the start of FDE range `[0x537b870, 0x537c677)` reaches that instruction boundary. The FDE itself is at `0x1347a8c`.

At `0x64a7f08` (file offset `0x64a5f08`), an `R_X86_64_RELATIVE` relocation points to `0x44e7fd` in `.rodata`. The next 16 bytes, `1f00000000000000e700000009000000`, decode as a little-endian 64-bit length of 31 and two 32-bit values, 231 and 9. The string's normalized suffix matches `l1/raw_signature_tracker.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x537be88` is `0x537beb3` and the fallthrough is `0x537be8a`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rcx, rcx`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x537be85` | `4885c9` | `test rcx, rcx` |
| `0x537be88` | `7429` | `je 0x537beb3` |
| `0x537beb3` | `31d2` | `xor edx, edx` |
| `0x537beb5` | `31c0` | `xor eax, eax` |
| `0x537beb7` | `31f6` | `xor esi, esi` |
| `0x537beb9` | `498b4d20` | `mov rcx, qword ptr [r13 + 0x20]` |
| `0x537bebd` | `488d3c92` | `lea rdi, [rdx + rdx*4]` |
| `0x537bec1` | `48c1e704` | `shl rdi, 4` |
| `0x537bec5` | `4801cf` | `add rdi, rcx` |
| `0x537bec8` | `488d0480` | `lea rax, [rax + rax*4]` |
| `0x537becc` | `48c1e004` | `shl rax, 4` |
| `0x537bed0` | `4801c8` | `add rax, rcx` |
| `0x537bed3` | `488d14b6` | `lea rdx, [rsi + rsi*4]` |
| `0x537bed7` | `48c1e204` | `shl rdx, 4` |
| `0x537bedb` | `4801ca` | `add rdx, rcx` |
| `0x537bede` | `41b802000000` | `mov r8d, 2` |
| `0x537bee4` | `4c89442430` | `mov qword ptr [rsp + 0x30], r8` |
| `0x537bee9` | `48897c2438` | `mov qword ptr [rsp + 0x38], rdi` |
| `0x537beee` | `4889442440` | `mov qword ptr [rsp + 0x40], rax` |
| `0x537bef3` | `48894c2448` | `mov qword ptr [rsp + 0x48], rcx` |
| `0x537bef8` | `4889542450` | `mov qword ptr [rsp + 0x50], rdx` |
| `0x537befd` | `48c744245800000000` | `mov qword ptr [rsp + 0x58], 0` |
| `0x537bf06` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x537bf0b` | `48894c2468` | `mov qword ptr [rsp + 0x68], rcx` |
| `0x537bf10` | `4889742470` | `mov qword ptr [rsp + 0x70], rsi` |
| `0x537bf15` | `488d8424ff010000` | `lea rax, [rsp + 0x1ff]` |
| `0x537bf1d` | `4889442478` | `mov qword ptr [rsp + 0x78], rax` |
| `0x537bf22` | `488d7c2430` | `lea rdi, [rsp + 0x30]` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed call displacement -5485987 added to `0x537bf33` gives `0x4e40990`. The target's FDE at `0x1303758` describes `[0x4e40990, 0x4e41504)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x537bf2e` | `e85d4aacff` | `call 0x4e40990` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64a7f08 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x537b870 --stop-address=0x537bf33 "$target"
od -An -tx1 -j 105537296 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e7fd --stop-address=0x44e81c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35dbbf1201`), re-decoding lands at `0x64a7f09`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 231, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
