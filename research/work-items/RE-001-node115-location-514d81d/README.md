# RE-001: anchor node #115 info_server/f_types/position.rs source-location reference

- Component allocation: `info-api`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `info_server/f_types/position.rs` as an embedded path. At ELF VA `0x514d81d` (file offset `0x514c81d`), `488d3dd4523501` decodes as `lea rdi, [rip + 0x13552d4]`. Adding the signed displacement `20271828` to the next instruction VA `0x514d824` yields `0x64a2af8`. The decode from the start of FDE range `[0x514d080, 0x514d953)` reaches that instruction boundary. The FDE itself is at `0x1321ef4`.

At `0x64a2af8` (file offset `0x64a0af8`), an `R_X86_64_RELATIVE` relocation points to `0x44acf9` in `.rodata`. The next 16 bytes, `23000000000000003f00000044000000`, decode as a little-endian 64-bit length of 35 and two 32-bit values, 63 and 68. The string's normalized suffix matches `info_server/f_types/position.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64a2af8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x514d080 --stop-address=0x514d824 "$target"
od -An -tx1 -j 105515776 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44acf9 --stop-address=0x44ad1c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3dd5523501`), re-decoding lands at `0x64a2af9`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 63, column 68. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
