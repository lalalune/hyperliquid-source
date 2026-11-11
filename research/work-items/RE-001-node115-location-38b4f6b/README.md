# RE-001: anchor node #115 l1/clearinghouse/margin_table.rs source-location reference

- Component allocation: `risk`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `l1/clearinghouse/margin_table.rs` as an embedded path. At ELF VA `0x38b4f6b` (file offset `0x38b3f6b`), `488d3d0e94bb02` decodes as `lea rdi, [rip + 0x2bb940e]`. Adding the signed displacement `45847566` to the next instruction VA `0x38b4f72` yields `0x646e380`. The decode from the start of FDE range `[0x38b4e20, 0x38b4f7a)` reaches that instruction boundary. The FDE itself is at `0x121dc1c`.

At `0x646e380` (file offset `0x646c380`), an `R_X86_64_RELATIVE` relocation points to `0x4441e4` in `.rodata`. The next 16 bytes, `24000000000000008b00000039000000`, decode as a little-endian 64-bit length of 36 and two 32-bit values, 139 and 57. The string's normalized suffix matches `l1/clearinghouse/margin_table.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*646e380 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x38b4e20 --stop-address=0x38b4f72 "$target"
od -An -tx1 -j 105300872 -N 16 "$target"
objdump -s -j .rodata --start-address=0x4441e4 --stop-address=0x444208 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3d0f94bb02`), re-decoding lands at `0x646e381`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 139, column 57. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
