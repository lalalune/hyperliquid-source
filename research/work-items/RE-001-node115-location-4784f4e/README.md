# RE-001: anchor node #115 net_utils/tcp/lz4_stats.rs source-location reference

- Component allocation: `transport`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `net_utils/tcp/lz4_stats.rs` as an embedded path. At ELF VA `0x4784f4e` (file offset `0x4783f4e`), `488d3d6327d101` decodes as `lea rdi, [rip + 0x1d12763]`. Adding the signed displacement `30484323` to the next instruction VA `0x4784f55` yields `0x64976b8`. The decode from the start of FDE range `[0x4784e90, 0x47855b4)` reaches that instruction boundary. The FDE itself is at `0x12c8d44`.

At `0x64976b8` (file offset `0x64956b8`), an `R_X86_64_RELATIVE` relocation points to `0x436ce6` in `.rodata`. The next 16 bytes, `1e00000000000000500000002a000000`, decode as a little-endian 64-bit length of 30 and two 32-bit values, 80 and 42. The string's normalized suffix matches `net_utils/tcp/lz4_stats.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64976b8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x4784e90 --stop-address=0x4784f55 "$target"
od -An -tx1 -j 105469632 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436ce6 --stop-address=0x436d04 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d6427d101`), re-decoding lands at `0x64976b9`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 80, column 42. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
