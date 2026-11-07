# RE-001: map node #115 db/db_hub.rs:25 conditional call edge

- Component allocation: `storage`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `db/db_hub.rs` as an embedded path. At ELF VA `0x38b3e43` (file offset `0x38b2e43`), `4c8d05eea4bb02` decodes as `lea r8, [rip + 0x2bba4ee]`. Adding the signed displacement `45851886` to the next instruction VA `0x38b3e4a` yields `0x646e338`. The decode from the start of FDE range `[0x38b3ad0, 0x38b3f8c)` reaches that instruction boundary. The FDE itself is at `0x121d9e4`.

At `0x646e338` (file offset `0x646c338`), an `R_X86_64_RELATIVE` relocation points to `0x4378d8` in `.rodata`. The next 16 bytes, `10000000000000001900000026000000`, decode as a little-endian 64-bit length of 16 and two 32-bit values, 25 and 38. The string's normalized suffix matches `db/db_hub.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x38b3b79` is `0x38b3e30` and the fallthrough is `0x38b3b7f`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rax, rax`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38b3b76` | `4885c0` | `test rax, rax` |
| `0x38b3b79` | `0f85b1020000` | `jne 0x38b3e30` |
| `0x38b3e30` | `4889442420` | `mov qword ptr [rsp + 0x20], rax` |
| `0x38b3e35` | `488d3ddcd7eefc` | `lea rdi, [rip - 0x3112824]` |
| `0x38b3e3c` | `488d0db5acbb02` | `lea rcx, [rip + 0x2bbacb5]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 46315590 added to `0x38b3e5a` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x38b3e4a` | `488d542420` | `lea rdx, [rsp + 0x20]` |
| `0x38b3e4f` | `be2b000000` | `mov esi, 0x2b` |
| `0x38b3e54` | `ff1546b8c202` | `call qword ptr [rip + 0x2c2b846]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*646e338 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x38b3ad0 --stop-address=0x38b3e5a "$target"
od -An -tx1 -j 105300800 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4378d8 --stop-address=0x4378e8 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05efa4bb02`), re-decoding lands at `0x646e339`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 25, column 38. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
