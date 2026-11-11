# RE-001: map node #115 db/rocks_db.rs:58 conditional call edge

- Component allocation: `storage`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `db/rocks_db.rs` as an embedded path. At ELF VA `0x57c6e2f` (file offset `0x57c5e2f`), `4c8d055a9cce00` decodes as `lea r8, [rip + 0xce9c5a]`. Adding the signed displacement `13540442` to the next instruction VA `0x57c6e36` yields `0x64b0a90`. The decode from the start of FDE range `[0x57c6530, 0x57c70b4)` reaches that instruction boundary. The FDE itself is at `0x1376ac8`.

At `0x64b0a90` (file offset `0x64aea90`), an `R_X86_64_RELATIVE` relocation points to `0x43d17d` in `.rodata`. The next 16 bytes, `12000000000000003a00000031000000`, decode as a little-endian 64-bit length of 18 and two 32-bit values, 58 and 49. The string's normalized suffix matches `db/rocks_db.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x57c6dee` is `0x57c6dff` and the fallthrough is `0x57c6df0`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test rsi, rsi`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x57c6deb` | `4885f6` | `test rsi, rsi` |
| `0x57c6dee` | `740f` | `je 0x57c6dff` |
| `0x57c6dff` | `4c8b7c2410` | `mov r15, qword ptr [rsp + 0x10]` |
| `0x57c6e04` | `4c89ac24a0000000` | `mov qword ptr [rsp + 0xa0], r13` |
| `0x57c6e0c` | `488b442408` | `mov rax, qword ptr [rsp + 8]` |
| `0x57c6e11` | `48898424a8000000` | `mov qword ptr [rsp + 0xa8], rax` |
| `0x57c6e19` | `4c89bc24b0000000` | `mov qword ptr [rsp + 0xb0], r15` |
| `0x57c6e21` | `488d3d9bf416fb` | `lea rdi, [rip - 0x4e90b65]` |
| `0x57c6e28` | `488d0d219ece00` | `lea rcx, [rip + 0xce9e21]` |

## Argument flow

The LEA writes `r8`. The trace follows the unchanged value to the call. At the call, `r8` is SysV x86-64 integer argument register 5. The signed displacement 13731927 added to `0x57c6e49` gives the relocation slot `0x64df6a0`. Its symbol-zero RELATIVE addend is `0x1680c30`. The target's FDE at `0xcc3024` describes `[0x1680c30, 0x1680c82)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x57c6e36` | `488d9424a0000000` | `lea rdx, [rsp + 0xa0]` |
| `0x57c6e3e` | `be2b000000` | `mov esi, 0x2b` |
| `0x57c6e43` | `ff155788d100` | `call qword ptr [rip + 0xd18857]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b0a90 '
readelf -rW "$target" | grep -i '0*64df6a0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x57c6530 --stop-address=0x57c6e49 "$target"
od -An -tx1 -j 105573016 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43d17d --stop-address=0x43d18f "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d055b9cce00`), re-decoding lands at `0x64b0a91`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 58, column 49. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
