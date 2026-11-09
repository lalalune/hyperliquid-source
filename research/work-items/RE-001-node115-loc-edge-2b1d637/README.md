# RE-001: map node #115 base/shell.rs:129 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/shell.rs` as an embedded path. At ELF VA `0x2b1d637` (file offset `0x2b1c637`), `488d35929c9203` decodes as `lea rsi, [rip + 0x3929c92]`. Adding the signed displacement `59939986` to the next instruction VA `0x2b1d63e` yields `0x64472d0`. The decode from the start of FDE range `[0x2b1d460, 0x2b1d993)` reaches that instruction boundary. The FDE itself is at `0x117f54c`.

At `0x64472d0` (file offset `0x64452d0`), an `R_X86_64_RELATIVE` relocation points to `0x449b13` in `.rodata`. The next 16 bytes, `1100000000000000810000002a000000`, decode as a little-endian 64-bit length of 17 and two 32-bit values, 129 and 42. The string's normalized suffix matches `base/shell.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2b1d600` is `0x2b1d61d` and the fallthrough is `0x2b1d602`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp eax, 1`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2b1d5fd` | `83f801` | `cmp eax, 1` |
| `0x2b1d600` | `741b` | `je 0x2b1d61d` |
| `0x2b1d61d` | `6441c6464400` | `mov byte ptr fs:[r14 + 0x44], 0` |
| `0x2b1d623` | `4c896c2440` | `mov qword ptr [rsp + 0x40], r13` |
| `0x2b1d628` | `48896c2448` | `mov qword ptr [rsp + 0x48], rbp` |
| `0x2b1d62d` | `0f28442460` | `movaps xmm0, xmmword ptr [rsp + 0x60]` |
| `0x2b1d632` | `0f11442450` | `movups xmmword ptr [rsp + 0x50], xmm0` |

## Argument flow

The LEA writes `rsi`. The trace follows the unchanged value to the call. At the call, `rsi` is SysV x86-64 integer argument register 2. The signed displacement 60568535 added to `0x2b1d649` gives the relocation slot `0x64e0a20`. Its symbol-zero RELATIVE addend is `0x1535fd0`. The target's FDE at `0x104e31c` describes `[0x1535fd0, 0x153661e)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2b1d63e` | `488d7c2440` | `lea rdi, [rsp + 0x40]` |
| `0x2b1d643` | `ff15d7339c03` | `call qword ptr [rip + 0x39c33d7]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64472d0 '
readelf -rW "$target" | grep -i '0*64e0a20 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2b1d460 --stop-address=0x2b1d649 "$target"
od -An -tx1 -j 105140952 -N 16 "$target"
objdump -s -j .rodata --start-address=0x449b13 --stop-address=0x449b24 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35939c9203`), re-decoding lands at `0x64472d1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 129, column 42. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
