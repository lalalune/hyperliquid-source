# RE-001: anchor node #115 l1/c_staking/jailing.rs source-location reference

- Component allocation: `staking`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `l1/c_staking/jailing.rs` as an embedded path. At ELF VA `0x3c36154` (file offset `0x3c35154`), `488d2d1d078402` decodes as `lea rbp, [rip + 0x284071d]`. Adding the signed displacement `42207005` to the next instruction VA `0x3c3615b` yields `0x6476878`. The decode from the start of FDE range `[0x3c35fe0, 0x3c36b95)` reaches that instruction boundary. The FDE itself is at `0x124403c`.

At `0x6476878` (file offset `0x6474878`), an `R_X86_64_RELATIVE` relocation points to `0x444e84` in `.rodata`. The next 16 bytes, `1b00000000000000c700000024000000`, decode as a little-endian 64-bit length of 27 and two 32-bit values, 199 and 36. The string's normalized suffix matches `l1/c_staking/jailing.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6476878 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x3c35fe0 --stop-address=0x3c3615b "$target"
od -An -tx1 -j 105334912 -N 16 "$target"
objdump -s -j .rodata --start-address=0x444e84 --stop-address=0x444e9f "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d2d1e078402`), re-decoding lands at `0x6476879`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 199, column 36. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
