# RE-001: anchor node #115 l1/bridge2.rs source-location reference

- Component allocation: `bridge`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `l1/bridge2.rs` as an embedded path. At ELF VA `0x44d7e3b` (file offset `0x44d6e3b`), `4c8d058e45fb01` decodes as `lea r8, [rip + 0x1fb458e]`. Adding the signed displacement `33244558` to the next instruction VA `0x44d7e42` yields `0x648c3d0`. The decode from the start of FDE range `[0x44d7b10, 0x44d7f07)` reaches that instruction boundary. The FDE itself is at `0xec24c0`.

At `0x648c3d0` (file offset `0x648a3d0`), an `R_X86_64_RELATIVE` relocation points to `0x43e33a` in `.rodata`. The next 16 bytes, `1100000000000000b100000028000000`, decode as a little-endian 64-bit length of 17 and two 32-bit values, 177 and 40. The string's normalized suffix matches `l1/bridge2.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648c3d0 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x44d7b10 --stop-address=0x44d7e42 "$target"
od -An -tx1 -j 105423832 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43e33a --stop-address=0x43e34b "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d058f45fb01`), re-decoding lands at `0x648c3d1`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 177, column 40. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
