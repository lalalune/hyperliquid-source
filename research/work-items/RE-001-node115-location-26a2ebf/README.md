# RE-001: anchor node #115 l1/abci/state.rs source-location reference

- Component allocation: `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `l1/abci/state.rs` as an embedded path. At ELF VA `0x26a2ebf` (file offset `0x26a1ebf`), `4c8d059a45d903` decodes as `lea r8, [rip + 0x3d9459a]`. Adding the signed displacement `64570778` to the next instruction VA `0x26a2ec6` yields `0x6437460`. The decode from the start of FDE range `[0x26a2c80, 0x26a326e)` reaches that instruction boundary. The FDE itself is at `0x112c590`.

At `0x6437460` (file offset `0x6435460`), an `R_X86_64_RELATIVE` relocation points to `0x443168` in `.rodata`. The next 16 bytes, `14000000000000009700000011000000`, decode as a little-endian 64-bit length of 20 and two 32-bit values, 151 and 17. The string's normalized suffix matches `l1/abci/state.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*6437460 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x26a2c80 --stop-address=0x26a2ec6 "$target"
od -An -tx1 -j 105075816 -N 16 "$target"
objdump -s -j .rodata --start-address=0x443168 --stop-address=0x44317c "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`4c8d059b45d903`), re-decoding lands at `0x6437461`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 151, column 17. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
