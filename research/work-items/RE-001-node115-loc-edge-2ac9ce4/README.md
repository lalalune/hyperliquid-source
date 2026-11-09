# RE-001: map node #115 node/hl_node.rs:214 conditional call edge

- Component allocation: `node-runtime`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `node/hl_node.rs` as an embedded path. At ELF VA `0x2ac9ce4` (file offset `0x2ac8ce4`), `4c8d053de09703` decodes as `lea r8, [rip + 0x397e03d]`. Adding the signed displacement `60284989` to the next instruction VA `0x2ac9ceb` yields `0x6447d28`. The decode from the start of FDE range `[0x2ac9cb0, 0x2ac9d18)` reaches that instruction boundary. The FDE itself is at `0x117baa8`.

At `0x6447d28` (file offset `0x6445d28`), an `R_X86_64_RELATIVE` relocation points to `0x436a23` in `.rodata`. The next 16 bytes, `1300000000000000d600000038000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 214 and 56. The string's normalized suffix matches `node/hl_node.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2ac9cbb` is `0x2ac9ccd` and the fallthrough is `0x2ac9cbd`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp dword ptr [rsi], 0xe2`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ac9cb5` | `813ee2000000` | `cmp dword ptr [rsi], 0xe2` |
| `0x2ac9cbb` | `7410` | `je 0x2ac9ccd` |
| `0x2ac9ccd` | `488b4608` | `mov rax, qword ptr [rsi + 8]` |
| `0x2ac9cd1` | `4889442408` | `mov qword ptr [rsp + 8], rax` |
| `0x2ac9cd6` | `488d3df7bfb3fd` | `lea rdi, [rip - 0x24c4009]` |
| `0x2ac9cdd` | `488d0de4d69703` | `lea rcx, [rip + 0x397d6e4]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 60905893 added to `0x2ac9cfb` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2ac9ceb` | `488d542408` | `lea rdx, [rsp + 8]` |
| `0x2ac9cf0` | `be16000000` | `mov esi, 0x16` |
| `0x2ac9cf5` | `ff15a559a103` | `call qword ptr [rip + 0x3a159a5]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6447d28 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2ac9cb0 --stop-address=0x2ac9cfb "$target"
od -An -tx1 -j 105143600 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436a23 --stop-address=0x436a36 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d053ee09703`), re-decoding lands at `0x6447d29`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 214, column 56. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
