# RE-001: anchor node #115 base/chain_ext.rs source-location reference

- Component allocation: `foundation`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `base/chain_ext.rs` as an embedded path. At ELF VA `0x14cdae8` (file offset `0x14ccae8`), `488d15d9c9f204` decodes as `lea rdx, [rip + 0x4f2c9d9]`. Adding the signed displacement `83020249` to the next instruction VA `0x14cdaef` yields `0x63fa4c8`. The decode from the start of FDE range `[0x14cd400, 0x14cdb33)` reaches that instruction boundary. The FDE itself is at `0x1047c08`.

At `0x63fa4c8` (file offset `0x63f84c8`), an `R_X86_64_RELATIVE` relocation points to `0x4376e7` in `.rodata`. The next 16 bytes, `15000000000000002700000019000000`, decode as a little-endian 64-bit length of 21 and two 32-bit values, 39 and 25. The string's normalized suffix matches `base/chain_ext.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*63fa4c8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x14cd400 --stop-address=0x14cdaef "$target"
od -An -tx1 -j 104826064 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4376e7 --stop-address=0x4376fc "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d15dac9f204`), re-decoding lands at `0x63fa4c9`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 39, column 25. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
