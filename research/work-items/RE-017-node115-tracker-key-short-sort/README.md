# Node #115: short 20-byte tracker-key sort dispatch and insertion

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This extends the tracker-key run-discovery packet into its previously unexamined short-run helper.

At `0x3e4abdb..0x3e4ac21`, when the flag at stack offset `0x4c` is nonzero and the remaining length falls below the run threshold, the caller passes at most 32 entries to slot `0x64e9e48`. Its pinned `R_X86_64_RELATIVE` relocation points to `0x42e4a30`; that helper dispatches lengths below 33 to `0x43893e0`. At the latter entry lengths below two return, and otherwise scratch capacity below `length + 16` reaches `ud2`. These are observations about this call chain, not every caller.

For lengths 2 through 7, `0x4389689..0x43897c2` initializes one entry in each scratch half and incrementally inserts additional 20-byte entries. In the first half an entry is shifted left only while `memcmp(new, previous, 20)` is negative: equal entries stop shifting. The named import is identified by the pinned relocation at `0x64dfb50`. The second half uses a parallel insertion path; the halves are subsequently merged. Buffer validity, normal import behavior and the capacity check are prerequisites.

The four-at-a-time path for lengths 8–32, final merge details, the caller flag's provenance, runtime bindings and global stability remain open; this packet does not claim a complete sorter or execution equivalence.

Run `python3 research/work-items/RE-017-node115-tracker-key-short-sort/verify.py` to check target digest, anchors and mutations without target execution. `windows.txt` records disassembly and relocations.
