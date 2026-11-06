# RE-001: anchor node #115 db/db_home.rs source-location reference

- Component allocation: `storage`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `db/db_home.rs` as an embedded path. At ELF VA `0x59ffaaf` (file offset `0x59feaaf`), `488d0dc283ab00` decodes as `lea rcx, [rip + 0xab83c2]`. Adding the signed displacement `11240386` to the next instruction VA `0x59ffab6` yields `0x64b7e78`. The decode from the start of FDE range `[0x59ffa30, 0x5a007bb)` reaches that instruction boundary. The FDE itself is at `0x13a0944`.

At `0x64b7e78` (file offset `0x64b5e78`), an `R_X86_64_RELATIVE` relocation points to `0x448051` in `.rodata`. The next 16 bytes, `11000000000000001500000018000000`, decode as a little-endian 64-bit length of 17 and two 32-bit values, 21 and 24. The string's normalized suffix matches `db/db_home.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b7e78 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x59ffa30 --stop-address=0x59ffab6 "$target"
od -An -tx1 -j 105602688 -N 16 "$target"
objdump -s -j .rodata --start-address=0x448051 --stop-address=0x448062 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d0dc383ab00`), re-decoding lands at `0x64b7e79`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 21, column 24. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
