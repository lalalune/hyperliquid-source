# RE-001: anchor node #115 node/consensus/latency_samplers.rs source-location reference

- Component allocation: `consensus`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `node/consensus/latency_samplers.rs` as an embedded path. At ELF VA `0x57e7642` (file offset `0x57e6642`), `488d154796cc00` decodes as `lea rdx, [rip + 0xcc9647]`. Adding the signed displacement `13407815` to the next instruction VA `0x57e7649` yields `0x64b0c90`. The decode from the start of FDE range `[0x57e73d0, 0x57e7715)` reaches that instruction boundary. The FDE itself is at `0x137b2c8`.

At `0x64b0c90` (file offset `0x64aec90`), an `R_X86_64_RELATIVE` relocation points to `0x439f0b` in `.rodata`. The next 16 bytes, `26000000000000002600000015000000`, decode as a little-endian 64-bit length of 38 and two 32-bit values, 38 and 21. The string's normalized suffix matches `node/consensus/latency_samplers.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*64b0c90 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x57e73d0 --stop-address=0x57e7649 "$target"
od -An -tx1 -j 105573528 -N 16 "$target"
objdump -s -j .rodata --start-address=0x439f0b --stop-address=0x439f31 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d154896cc00`), re-decoding lands at `0x64b0c91`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 38, column 21. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
