# Node #115 raw-map insertion into a nonfull leaf

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static inspection only; FDE range recorded in `RE-001-owner-tail-phases-115/callers.tsv` is `0x4c3f280..0x4c3fde6`. The output here covers only the branch below.

The raw-map insertion helper `0x51ef9a0` calls `0x4c3f280` for a non-null descriptor node, passing the key, 12-byte value and selected index. At `0x4c3f29a` the callee reads node count; a count of 11 or greater takes the separate split path. Assuming a valid node, non-aliasing input and an insertion index i between zero and count n < 11, the nonfull path does the following:

* At i = n it writes the key into the next key slot.
* At i < n, `0x4c3f2f5..0x4c3f329` makes an indirect move call over `8*(n-i)` bytes from key slot i to slot i+1, then writes the new key at i. `0x4c3f32e..0x4c3f355` similarly requests a move over `12*(n-i)` bytes for the value slots.
* `0x4c3f36b..0x4c3f383` writes the supplied 12 bytes into value slot i and stores count n+1 at node +0xe6.

The indirect move calls use slot `0x64df568`, which the pinned ELF dynamic relocation table identifies as `memmove@GLIBC_2.2.5` (`R_X86_64_GLOB_DAT`). This identifies the imported symbol, not a runtime binding or behavior under malformed pointers. Full-node split, allocation failure, malformed descriptor, and runtime reachability remain outside scope. The separately reported absent-key tree search establishes how the insertion index is supplied; these observations do not establish complete tree equivalence.

Reproduction: `python3 research/work-items/RE-017-node115-raw-map-leaf-insert/verify.py` checks the whole-file target digest, instruction and call anchors, and rejects mutated anchors without target execution. `windows.txt` was generated with Apple `objdump -d --x86-asm-syntax=intel`.
