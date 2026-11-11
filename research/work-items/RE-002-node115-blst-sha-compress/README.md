# RE-002 · Node #115 blst SHA-256 compression linkage

Component: foundation utilities, native dependency provenance. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Repository baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

The [CPU dispatch evidence](https://github.com/lalalune/hyperliquid-source/pull/3011) locates the capability word and two branches into SHA instructions. This packet checks the complete compression bodies and the operands that differ when the same reference is assembled as a relocatable object.

## Results

The three reference symbols each coincide with a complete target FDE. The [transcript](evidence.txt) records all ranges, raw matches and six `R_X86_64_PC32` fixups. There are **8,958 raw-equal bytes out of 8,980**. All 8,980 bytes match after applying the six relocations to the reference object bytes.

The 362-byte reference `.rodata` occurs once in the target section, at `0x956d80`. That match independently supplies the address for the four table relocations. The other two fixups resolve to the observed CPU capability word at `0x65000d0`. The dispatch taken target `0x5d21248` is eight bytes inside the reference SHA extension symbol, at the same local label used by the assembled reference. Changing one relocation's symbol address per body makes the comparison fail.

The result identifies these three bodies and their table bindings. It does not select an exclusive blst revision, run a digest test against the captured code, or update the registry's coverage accounting or acceptance gates.

## Reproduction

Use the public, Apache-2.0 blst revision `e7f90de551e8df682f3cc99067d204d8b90d27ad`. Put the following pinned files in a scratch directory. The include order and rename follow that revision's [assembly driver](https://github.com/supranational/blst/blob/e7f90de551e8df682f3cc99067d204d8b90d27ad/build/assembly.S).

- [sha256-portable-x86_64.s](https://github.com/supranational/blst/blob/e7f90de551e8df682f3cc99067d204d8b90d27ad/build/elf/sha256-portable-x86_64.s) — SHA-256 `25b7d54b248a1ccb910d4abb8a45ea82d7bdc78e48162b80e492dd5f2100a03c`.
- [sha256-x86_64.s](https://github.com/supranational/blst/blob/e7f90de551e8df682f3cc99067d204d8b90d27ad/build/elf/sha256-x86_64.s) — SHA-256 `0216306f90681189d9ecdcc126cca8da58497cd89f9a91b221317101755d1579`.

Build with Zig 0.15.2, then run the comparison with Python 3.11+ and pyelftools 0.33. Check the target's FDE extents against the transcript using readelf.

```sh
cat > sha-assembly.S <<'EOF'
#include "sha256-portable-x86_64.s"
#define blst_sha256_block_data_order blst_sha256_block_ssse3
#include "sha256-x86_64.s"
EOF
zig cc -target x86_64-linux-gnu -D__BLST_PORTABLE__ -x assembler-with-cpp -c sha-assembly.S -o ref.o
python3 -B /path/to/verify.py ref.o /path/to/hl-node
readelf --debug-dump=frames-interp /path/to/hl-node
```
