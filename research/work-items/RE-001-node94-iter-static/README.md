# Node #94 iterator-associated value consistency

Question: how does one iterator-associated body select and check equal-key values, and which result tags are actually written?

The single exact FDE is [0x33690c0,0x33694fc). Its mismatch diagnostic passes Location 0x56e9e38, whose RELATIVE addend is the exact 45-byte base/src/iter.rs path, line 132 column 21. The mismatch block is reached from 0x336942c and calls slot 0x576e098, relocated to 0x157b810. The alternate exceptional helper at 0x33694f2 uses slot 0x576e470 -> 0x157a9f0. Helper semantics are not closed.

At 0x3369367 the record index is shifted by six. SIMD loads compare 16 bytes at record+0x18 against input+0, then four bytes at record+0x28 against input+0x10; combined equality mask must equal 0xffff. Failure loops to 0x3369190. Matching records address a 32-byte value using index<<5 plus 0x2c0. Once the retained-value flag is set, two 16-byte comparisons check the retained and current 32-byte values; mismatch reaches 0x33694b2. This supports an inferred first-value consistency operation; it does not identify the collection's Rust type or prove its full traversal.

Observed AX writes are 0x97 for absent root; 0x2a at exhausted/empty selection; and 0x186 after copying 32 bytes into output+2 (two 16-byte stores). Common exit stores AX at output+0. These are raw tags, not named enum variants. Tree fields at +0x420/+0x428/+0x42a/+0x430 and child traversal are observed but not attributed to a recovered type. Next step: validate callers and enclosing output ABI before naming the tags.

Task RE-001; component foundation. Static research only. Source revision 1f8c67c63ca4794c9689235471c60297f8a5c985; reference 999556f6e0a474b8312db96ec3149e1c44e97c23. Reference is inferred and unlicensed: no reference implementation was copied. New tools/tests/docs independently authored under repository MIT.

Target Linux x86-64 node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. All addresses are ELF virtual addresses, ends exclusive; file offsets and body digests are recorded in observed/records.json. No normalization. No captured binary execution. No Rust implementation/equivalence claim. All four foundation progress gates remain false. Comparison denominator is one FDE-validated research body; accepted raw-equal/normalized-only/unmatched reconstruction counts are unmeasured.

## Reproduce and controls

Tools: GNU objdump (GNU Binutils for Ubuntu) 2.42; GNU readelf (GNU Binutils for Ubuntu) 2.42; Python 3.12.3. GNU objdump -d with explicit start/stop addresses; GNU readelf -wf and -rW.

```sh
python3 tools/iter_value_consistency_static.py --output work/iter-94
python3 tools/iter_value_consistency_static.py --output work/iter-repeat-94
diff -r work/iter-94 work/iter-repeat-94
make doctor verify test catalogue-check reproduce
```

Full target digest/size is checked before analysis. Tests call lower-level validators on authentic bytes with individual instruction/literal flips and relocation retargets, bypassing the full-file hash so controls exercise their intended validators. Decoded objdump checks separately bind branch destinations, operand widths and raw tags/cutoffs. These static controls validate the packet, not runtime equivalence.

Before: no packet for this bounded body. After: one exact FDE, raw disassembly/FDE/RELA exports and independently reproducible digest-bound records. Initial verify failed because newly materialized local LFS reference retained stale index state; clean+local renormalization restored the unchanged pointer index. A separate optional git-lfs fsck --pointers crashed in local git-lfs and is not claimed as passing. No imports/pins were changed. Hosted CI/container/Ghidra were not run; doctor reports provider availability as observed.

Native checkout setup uses local LFS filters and locally ignores executable-mode differences from authenticated hardlinked artifact materialization; the committed artifact/index modes, bytes and reference revisions are unchanged. Working directory for all commands is the repository root; Linux x86-64, existing Python/GNU binutils and Git LFS required. No dependency install or global environment change.

Final validation: make doctor verify test catalogue-check reproduce returned 0; 437 full tests in 159.600s. Final targeted suite six tests passed. Repeated final producer exports are byte-identical.

After correcting only the tool module description, the final focused six tests passed and repeated producer exports were identical to the pre-correction exports. The full 437-test suite passed before this description-only correction.
