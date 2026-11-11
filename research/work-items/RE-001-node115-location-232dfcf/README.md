# RE-001: anchor node #115 evm_rpc/evm_store.rs source-location reference

- Component allocation: `evm-rpc`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`. No external source revision or implementation comparison.
- Scope: one decoded instruction, its enclosing unwind range, and one source-location-shaped data record.

## Observation

The component catalogue lists `evm_rpc/evm_store.rs` as an embedded path. At ELF VA `0x232dfcf` (file offset `0x232cfcf`), `488d1572fc0f04` decodes as `lea rdx, [rip + 0x40ffc72]`. Adding the signed displacement `68156530` to the next instruction VA `0x232dfd6` yields `0x642dc48`. The decode from the start of FDE range `[0x232df90, 0x232dfee)` reaches that instruction boundary. The FDE itself is at `0xd00b00`.

At `0x642dc48` (file offset `0x642bc48`), an `R_X86_64_RELATIVE` relocation points to `0x44801d` in `.rodata`. The next 16 bytes, `1800000000000000c40100003d000000`, decode as a little-endian 64-bit length of 24 and two 32-bit values, 452 and 61. The string's normalized suffix matches `evm_rpc/evm_store.rs`. [record.json](record.json) preserves the coordinates and instruction bytes.

## Reproduce

Run from the repository root with the LFS target materialized. Virtual addresses are link-time ELF VAs.

```sh
target=artifacts/node/115/hl-node
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 "$target" | sha256sum -c -
readelf -rW "$target" | grep -i '0*642dc48 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x232df90 --stop-address=0x232dfd6 "$target"
od -An -tx1 -j 105036880 -N 16 "$target"
objdump -s -j .rodata --start-address=0x44801d --stop-address=0x448035 "$target"
```

Local extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 on Windows. The extractor decoded from the FDE start and read the relocation and data bytes directly. The independent GNU commands above are review steps. With the disp32 changed by +1 in memory (`488d1573fc0f04`), re-decoding lands at `0x642dc49`, which fails the exact descriptor-address check.

## Interpretation and limits

The data layout is consistent with Rust source-location metadata for line 452, column 61. The code reference provides a starting point for locating uses of that source path. The enclosing function's identity, reachability, and the eventual consumer of the loaded pointer remain unresolved. Next, track the destination register through the containing block to determine whether it feeds a diagnostic call. No captured code was executed and no reconstruction gate or byte denominator is claimed.
