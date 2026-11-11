# RE-001: map node #115 db/owned_db_home.rs:21 conditional call edge

- Component allocation: `storage`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `db/owned_db_home.rs` as an embedded path. At ELF VA `0x1696257` (file offset `0x1695257`), `488d157229d704` decodes as `lea rdx, [rip + 0x4d72972]`. Adding the signed displacement `81209714` to the next instruction VA `0x169625e` yields `0x6408bd0`. The decode from the start of FDE range `[0x16961b0, 0x1696729)` reaches that instruction boundary. The FDE itself is at `0x1069df8`.

At `0x6408bd0` (file offset `0x6406bd0`), an `R_X86_64_RELATIVE` relocation points to `0x44f3db` in `.rodata`. The next 16 bytes, `17000000000000001500000009000000`, decode as a little-endian 64-bit length of 23 and two 32-bit values, 21 and 9. The string's normalized suffix matches `db/owned_db_home.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x1696350` is `0x169623f` and the fallthrough is `0x1696356`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test bpl, bpl`. The recorded edge is selected when the `jne` predicate (`ZF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x169634d` | `4084ed` | `test bpl, bpl` |
| `0x1696350` | `0f85e9feffff` | `jne 0x169623f` |
| `0x169623f` | `48895c2428` | `mov qword ptr [rsp + 0x28], rbx` |
| `0x1696244` | `488d0545ffffff` | `lea rax, [rip - 0xbb]` |
| `0x169624b` | `4889442430` | `mov qword ptr [rsp + 0x30], rax` |
| `0x1696250` | `488d3dd11bdbfe` | `lea rdi, [rip - 0x124e42f]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 82089039 added to `0x1696269` gives the relocation slot `0x64df6b8`. Its symbol-zero RELATIVE addend is `0x1680e80`. The target's FDE at `0xcc3104` describes `[0x1680e80, 0x1680eac)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x169625e` | `488d742428` | `lea rsi, [rsp + 0x28]` |
| `0x1696263` | `ff154f94e404` | `call qword ptr [rip + 0x4e4944f]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6408bd0 '
readelf -rW "$target" | grep -i '0*64df6b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x16961b0 --stop-address=0x1696356 "$target"
od -An -tx1 -j 104885208 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44f3db --stop-address=0x44f3f2 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d157329d704`), re-decoding lands at `0x6408bd1`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 21, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
