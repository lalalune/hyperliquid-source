# RE-001: map node #115 db/rocks_db.rs:58 conditional call edge

- Component allocation: `storage`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `db/rocks_db.rs` as an embedded path. At ELF VA `0x45249a3` (file offset `0x45239a3`), `4c8d05b6a8f601` decodes as `lea r8, [rip + 0x1f6a8b6]`. Adding the signed displacement `32942262` to the next instruction VA `0x45249aa` yields `0x648f260`. The decode from the start of FDE range `[0x4524660, 0x4524adb)` reaches that instruction boundary. The FDE itself is at `0x12aa484`.

At `0x648f260` (file offset `0x648d260`), an `R_X86_64_RELATIVE` relocation points to `0x43d17d` in `.rodata`. The next 16 bytes, `12000000000000003a00000031000000`, decode as a little-endian 64-bit length of 18 and two 32-bit values, 58 and 49. The string's normalized suffix matches `db/rocks_db.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x452488e` is `0x452497e` and the fallthrough is `0x4524894`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rax, qword ptr [rsp + 0x68]`. The recorded edge is selected when the `jo` predicate (`OF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4524889` | `483b442468` | `cmp rax, qword ptr [rsp + 0x68]` |
| `0x452488e` | `0f80ea000000` | `jo 0x452497e` |
| `0x452497e` | `488b842480000000` | `mov rax, qword ptr [rsp + 0x80]` |
| `0x4524986` | `4889442460` | `mov qword ptr [rsp + 0x60], rax` |
| `0x452498b` | `0f10442470` | `movups xmm0, xmmword ptr [rsp + 0x70]` |
| `0x4524990` | `0f29442450` | `movaps xmmword ptr [rsp + 0x50], xmm0` |
| `0x4524995` | `488d3d0cf32afc` | `lea rdi, [rip - 0x3d50cf4]` |
| `0x452499c` | `488d0d5da9f601` | `lea rcx, [rip + 0x1f6a95d]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 33271014 added to `0x45249ba` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x45249aa` | `488d542450` | `lea rdx, [rsp + 0x50]` |
| `0x45249af` | `be2b000000` | `mov esi, 0x2b` |
| `0x45249b4` | `ff15e6acfb01` | `call qword ptr [rip + 0x1fbace6]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648f260 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4524660 --stop-address=0x45249ba "$target"
od -An -tx1 -j 105435752 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43d17d --stop-address=0x43d18f "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d05b7a8f601`), re-decoding lands at `0x648f261`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 58, column 49. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
