# RE-001: anchor node #115 l1/book/book/impl_insert_order.rs source-location reference

- Component allocation: `orderbook`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `l1/book/book/impl_insert_order.rs` as an embedded path. At ELF VA `0x23f5e38` (file offset `0x23f4e38`), `488d3da99a0304` decodes as `lea rdi, [rip + 0x4039aa9]`. Adding the signed displacement `67345065` to the next instruction VA `0x23f5e3f` yields `0x642f8e8`. The decode from the start of FDE range `[0x23f5460, 0x23f64bc)` reaches that instruction boundary. The FDE itself is at `0x1108368`.

At `0x642f8e8` (file offset `0x642d8e8`), an `R_X86_64_RELATIVE` relocation points to `0x436955` in `.rodata`. The next 16 bytes, `2500000000000000e80200005b000000`, decode as a little-endian 64-bit length of 37 and two 32-bit values, 744 and 91. The string's normalized suffix matches `l1/book/book/impl_insert_order.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*642f8e8 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x23f5460 --stop-address=0x23f5e3f "$target"
od -An -tx1 -j 105044208 -N 16 "$target"
objdump -s -j .rodata --start-address=0x436955 --stop-address=0x43697a "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d3daa9a0304`), re-decoding lands at `0x642f8e9`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 744, column 91. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
