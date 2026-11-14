# Node #115: selected membership-set leaf deletion

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This enters the leaf case of the removal helper reached from the selected membership update in #6759.

On an exact match, `0x51d8758` calls `0x4d317e0`, which passes a height-zero selected node/index to `0x4d17720` at `0x4d319dd`. For a valid leaf with N entries and selected index i, `0x4d1773c..0x4d17790` saves the 20-byte entry, calls slot `0x64df568` with source at the next entry and destination at the current entry, byte length `20*(N-i-1)`, and stores node count `N-1`. The pinned ELF relocation identifies the slot as `memmove@GLIBC_2.2.5`, needed for overlapping shifts. If the new count exceeds four the selected path proceeds to the output copy; count four or below enters additional parent/root handling.

At `0x4d1794b..0x4d1797f`, the saved 20-byte removed value is copied to the result. Back in the caller, normal completion decrements the object count once and returns one, as separately traced in #6759. The no-parent/root and rebalancing branches are not reconstructed; this packet does not assert full tree correctness, valid-index checks, key identity or runtime reachability.

Run `python3 research/work-items/RE-017-node115-membership-leaf-delete/verify.py` to check target digest, selected anchors, direct calls and mutation controls without target execution. `windows.txt` contains the static windows and `memmove` relocation.
