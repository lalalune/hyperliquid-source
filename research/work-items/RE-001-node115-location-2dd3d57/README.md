# RE-001: anchor node #115 l1/qtys/impl_sz.rs source-location reference

- Component allocation: `assets`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `l1/qtys/impl_sz.rs` as an embedded path. At ELF VA `0x2dd3d57` (file offset `0x2dd2d57`), `488d35ead36703` decodes as `lea rsi, [rip + 0x367d3ea]`. Adding the signed displacement `57136106` to the next instruction VA `0x2dd3d5e` yields `0x6451148`. The decode from the start of FDE range `[0x2dd34f0, 0x2dd3fa6)` reaches that instruction boundary. The FDE itself is at `0x11a63cc`.

At `0x6451148` (file offset `0x644f148`), an `R_X86_64_RELATIVE` relocation points to `0x446e52` in `.rodata`. The next 16 bytes, `16000000000000000900000001000000`, decode as a little-endian 64-bit length of 22 and two 32-bit values, 9 and 1. The string's normalized suffix matches `l1/qtys/impl_sz.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6451148 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2dd34f0 --stop-address=0x2dd3d5e "$target"
od -An -tx1 -j 105181520 -N 16 "$target"
objdump -s -j .rodata --start-address=0x446e52 --stop-address=0x446e68 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d35ebd36703`), re-decoding lands at `0x6451149`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 9, column 1. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
