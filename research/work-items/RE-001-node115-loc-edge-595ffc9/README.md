# RE-001: map node #115 node/consensus/types.rs:119 conditional call edge

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/consensus/types.rs` as an embedded path. At ELF VA `0x595ffc9` (file offset `0x595efc9`), `488d15e068b500` decodes as `lea rdx, [rip + 0xb568e0]`. Adding the signed displacement `11888864` to the next instruction VA `0x595ffd0` yields `0x64b68b0`. The decode from the start of FDE range `[0x595fd20, 0x596000d)` reaches that instruction boundary. The FDE itself is at `0x1390fbc`.

At `0x64b68b0` (file offset `0x64b48b0`), an `R_X86_64_RELATIVE` relocation points to `0x43b044` in `.rodata`. The next 16 bytes, `1b000000000000007700000011000000`, decode as a little-endian 64-bit length of 27 and two 32-bit values, 119 and 17. The string's normalized suffix matches `node/consensus/types.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x595fdb0` is `0x595ff78` and the fallthrough is `0x595fdb6`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp ecx, 0x2e`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x595fdad` | `83f92e` | `cmp ecx, 0x2e` |
| `0x595fdb0` | `0f84c2010000` | `je 0x595ff78` |
| `0x595ff78` | `4983c720` | `add r15, 0x20` |
| `0x595ff7c` | `410f104650` | `movups xmm0, xmmword ptr [r14 + 0x50]` |
| `0x595ff81` | `0f298424c0000000` | `movaps xmmword ptr [rsp + 0xc0], xmm0` |
| `0x595ff89` | `488d8424c0000000` | `lea rax, [rsp + 0xc0]` |
| `0x595ff91` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x595ff96` | `488b0523a7b800` | `mov rax, qword ptr [rip + 0xb8a723]` |
| `0x595ff9d` | `4889442410` | `mov qword ptr [rsp + 0x10], rax` |
| `0x595ffa2` | `4c897c2418` | `mov qword ptr [rsp + 0x18], r15` |
| `0x595ffa7` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |
| `0x595ffac` | `488d442470` | `lea rax, [rsp + 0x70]` |
| `0x595ffb1` | `4889442428` | `mov qword ptr [rsp + 0x28], rax` |
| `0x595ffb6` | `488d051307feff` | `lea rax, [rip - 0x1f8ed]` |
| `0x595ffbd` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x595ffc2` | `488d3d107fadfa` | `lea rdi, [rip - 0x55280f0]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 12056285 added to `0x595ffdb` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x595ffd0` | `488d742408` | `lea rsi, [rsp + 8]` |
| `0x595ffd5` | `ff15ddf6b700` | `call qword ptr [rip + 0xb7f6dd]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b68b0 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x595fd20 --stop-address=0x595ffdb "$target"
od -An -tx1 -j 105597112 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43b044 --stop-address=0x43b05f "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15e168b500`), re-decoding lands at `0x64b68b1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 119, column 17. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
