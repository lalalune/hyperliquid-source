# RE-001: map node #115 l1/books.rs:14 conditional call edge

- Component allocation: `orderbook`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No external source revision or implementation comparison.
- Scope: one conditional call edge and its source-location record.

## Observation

The component catalogue lists `l1/books.rs` as an embedded path. At ELF VA `0x556c751` (file offset `0x556b751`), `488d15f09ef400` decodes as `lea rdx, [rip + 0xf49ef0]`. Adding the signed displacement `16031472` to the next instruction VA `0x556c758` yields `0x64b6648`. The decode from the start of FDE range `[0x556c5e0, 0x556c774)` reaches that instruction boundary. The FDE itself is at `0xf8576c`.

At `0x64b6648` (file offset `0x64b4648`), an `R_X86_64_RELATIVE` relocation points to `0x44e6b2` in `.rodata`. The next 16 bytes, `0f000000000000000e00000010000000`, decode as a little-endian 64-bit length of 15 and two 32-bit values, 14 and 16. The string's normalized suffix matches `l1/books.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Conditional edge

The taken target at branch `0x556c5fe` is `0x556c751` and the fallthrough is `0x556c604`. The **taken** edge reaches the location load along the instructions below.

The flags come from `cmp rdx, rsi`. The recorded edge is selected when the `jae` predicate (`CF = 0`) is **true**.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x556c5fb` | `4839f2` | `cmp rdx, rsi` |
| `0x556c5fe` | `0f834d010000` | `jae 0x556c751` |

## Argument flow

The LEA writes `rdx`. The trace follows the unchanged value to the call. At the call, `rdx` is SysV x86-64 integer argument register 3. The signed displacement 16199359 added to `0x556c761` gives the relocation slot `0x64df620`. Its symbol-zero RELATIVE addend is `0x1680cbf`. The target's FDE at `0xcc3078` describes `[0x1680cbf, 0x1680cfc)`.

| Instruction VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x556c758` | `4889df` | `mov rdi, rbx` |
| `0x556c75b` | `ff15bf2ef700` | `call qword ptr [rip + 0xf72ebf]` |

## Callee identification

The resolved callee selects the diagnostic ``index out of bounds: the len is {rsi} but the index is {rdi}``. Its bytes at `0x4400ef` are `20696e646578206f7574206f6620626f756e64733a20746865206c656e20697320c012206275742074686520696e64657820697320c000`. The wrapper's RIP-relative indirect call uses slot `0x64df6b8`, whose RELATIVE addend is the sink at `0x1680e80`. The wrapper trace and sink FDE are recorded alongside the source-location record.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b6648 '
readelf -rW "$target" | grep -i '0*64df620 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x556c5e0 --stop-address=0x556c761 "$target"
objdump -d -M intel --start-address=0x1680cbf --stop-address=0x1680cfc "$target"
objdump -s -j .rodata --start-address=0x4400ef --stop-address=0x440126 "$target"
readelf -rW "$target" | grep -i '0*64df6b8 '
od -An -tx1 -j 105596496 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44e6b2 --stop-address=0x44e6c1 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15f19ef400`), re-decoding lands at `0x64b6649`, which fails the exact descriptor-address check.

## Interpretation and limits

The layout is consistent with Rust source-location metadata for line 14, column 16. The observation establishes the value in an incoming register on this path. Runtime reachability and full callee behavior remain unresolved. Next, trace the incoming register through the callee to determine which record fields it consumes. No captured code was executed and no reconstruction gate or byte denominator is claimed.
