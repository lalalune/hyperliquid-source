# RE-001: map node #115 base/production.rs:106 conditional call edge

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `base/production.rs` as an embedded path. At ELF VA `0x1535424` (file offset `0x1534424`), `488d151d83ec04` decodes as `lea rdx, [rip + 0x4ec831d]`. Adding the signed displacement `82608925` to the next instruction VA `0x153542b` yields `0x63fd748`. The decode from the start of FDE range `[0x1534ff0, 0x15354ef)` reaches that instruction boundary. The FDE itself is at `0x104e168`.

At `0x63fd748` (file offset `0x63fb748`), an `R_X86_64_RELATIVE` relocation points to `0x447b5a` in `.rodata`. The next 16 bytes, `16000000000000006a00000009000000`, decode as a little-endian 64-bit length of 22 and two 32-bit values, 106 and 9. The string's normalized suffix matches `base/production.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x1535025` is `0x153541d` and the fallthrough is `0x153502b`. The **taken** edge reaches the location load along the instructions below.

The flags come from `test al, al`. The recorded edge is selected when the `je` predicate (`ZF = 1`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1535023` | `84c0` | `test al, al` |
| `0x1535025` | `0f84f2030000` | `je 0x153541d` |
| `0x153541d` | `488d3d3c16f3fe` | `lea rdi, [rip - 0x10ce9c4]` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 83534586 added to `0x1535436` gives the relocation slot `0x64df730`. Its symbol-zero RELATIVE addend is `0x1680e60`. The target's FDE at `0xcc30e8` describes `[0x1680e60, 0x1680e72)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x153542b` | `be3c000000` | `mov esi, 0x3c` |
| `0x1535430` | `ff15faa2fa04` | `call qword ptr [rip + 0x4faa2fa]` |

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fd748 '
readelf -rW "$target" | grep -i '0*64df730 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x1534ff0 --stop-address=0x1535436 "$target"
od -An -tx1 -j 104838992 -N 16 "$target"
objdump -s -j .rodata --start-address=0x447b5a --stop-address=0x447b70 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d151e83ec04`), re-decoding lands at `0x63fd749`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 106, column 9. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
