# RE-001: map node #115 base/fu.rs:256 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/fu.rs` as an embedded path. At ELF VA `0x2b2b5c1` (file offset `0x2b2a5c1`), `488d15400b8d03` decodes as `lea rdx, [rip + 0x38d0b40]`. Adding the signed displacement `59575104` to the next instruction VA `0x2b2b5c8` yields `0x63fc108`. The decode from the start of FDE range `[0x2b2b3f0, 0x2b2b8de)` reaches that instruction boundary. The FDE itself is at `0x1180170`.

At `0x63fc108` (file offset `0x63fa108`), an `R_X86_64_RELATIVE` relocation points to `0x43caab` in `.rodata`. The next 16 bytes, `0e000000000000000001000017000000`, decode as a little-endian 64-bit length of 14 and two 32-bit values, 256 and 23. The string's normalized suffix matches `base/fu.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x2b2b596` is `0x2b2b5bc` and the fallthrough is `0x2b2b598`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp eax, 1`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2b2b593` | `83f801` | `cmp eax, 1` |
| `0x2b2b596` | `7424` | `je 0x2b2b5bc` |
| `0x2b2b5bc` | `64c6454400` | `mov byte ptr fs:[rbp + 0x44], 0` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 60511247 added to `0x2b2b5d1` gives the relocation slot `0x64e09e0`. Its symbol-zero RELATIVE addend is `0x1505a50`. The target's FDE at `0xcb1468` describes `[0x1505a50, 0x1505b69)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x2b2b5c8` | `4c89ef` | `mov rdi, r13` |
| `0x2b2b5cb` | `ff150f549b03` | `call qword ptr [rip + 0x39b540f]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fc108 '
readelf -rW "$target" | grep -i '0*64e09e0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2b2b3f0 --stop-address=0x2b2b5d1 "$target"
od -An -tx1 -j 104833296 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43caab --stop-address=0x43cab9 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15410b8d03`), re-decoding lands at `0x63fc109`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 256, column 23. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
