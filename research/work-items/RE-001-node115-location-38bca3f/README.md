# RE-001: anchor node #115 l1/hyperliquidity.rs source-location reference

- Component allocation: `l1-shared`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `l1/hyperliquidity.rs` as an embedded path. At ELF VA `0x38bca3f` (file offset `0x38bba3f`), `488d3d821abb02` decodes as `lea rdi, [rip + 0x2bb1a82]`. Adding the signed displacement `45816450` to the next instruction VA `0x38bca46` yields `0x646e4c8`. The decode from the start of FDE range `[0x38bc000, 0x38bca91)` reaches that instruction boundary. The FDE itself is at `0x121e084`.

At `0x646e4c8` (file offset `0x646c4c8`), an `R_X86_64_RELATIVE` relocation points to `0x4481d6` in `.rodata`. The next 16 bytes, `1800000000000000680100001d000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 360 and 29. The string's normalized suffix matches `l1/hyperliquidity.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*646e4c8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x38bc000 --stop-address=0x38bca46 "$target"
od -An -tx1 -j 105301200 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4481d6 --stop-address=0x4481ee "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d831abb02`), re-decoding lands at `0x646e4c9`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 360, column 29. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
