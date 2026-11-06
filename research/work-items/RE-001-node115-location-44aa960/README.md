# RE-001: anchor node #115 l1/vault/mod.rs source-location reference

- Component allocation: `vaults`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `l1/vault/mod.rs` as an embedded path. At ELF VA `0x44aa960` (file offset `0x44a9960`), `488d3da917fe01` decodes as `lea rdi, [rip + 0x1fe17a9]`. Adding the signed displacement `33429417` to the next instruction VA `0x44aa967` yields `0x648c110`. The decode from the start of FDE range `[0x44a97b0, 0x44aad40)` reaches that instruction boundary. The FDE itself is at `0x12a622c`.

At `0x648c110` (file offset `0x648a110`), an `R_X86_64_RELATIVE` relocation points to `0x43e326` in `.rodata`. The next 16 bytes, `13000000000000000502000032000000`, decode as a little-endian 64-bit length of 19 and two 32-bit values, 517 and 50. The string's normalized suffix matches `l1/vault/mod.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*648c110 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x44a97b0 --stop-address=0x44aa967 "$target"
od -An -tx1 -j 105423128 -N 16 "$target"
objdump -s -j .rodata --start-address=0x43e326 --stop-address=0x43e339 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3daa17fe01`), re-decoding lands at `0x648c111`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 517, column 50. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
