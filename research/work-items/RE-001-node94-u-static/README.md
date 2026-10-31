# Node #94 path preparation and sort dispatch

Question: does this path reject a trailing slash, and how does its observed unsigned word sorting dispatch work?

The single exact FDE is [0x13ca0e0,0x13ca362). At 0x13ca100 the length is tested; a nonempty slice compares its final byte to 0x2f and branches to 0x13ca273. That block passes the 42-byte literal `assertion failed: !base_dir.ends_with('/')` at 0x216df0 and Location 0x5666b98. Its R_X86_64_RELATIVE pointer resolves to the exact 42-byte embedded base/src/u.rs source path, with line 400 column 9. This is a validated diagnostic attribution, not a recovered source signature.

At 0x13ca20b an unsigned length >=2 selects sorting; >=21 selects the indirect helper through slot 0x576e940, relocated to 0x148f1c0. Lengths 2..20 enter an insertion loop with 8-byte stride and unsigned comparisons: jae skips an already ordered pair; jb continues shifting predecessors. Both paths rejoin 0x13ca211. The diagnostic helper slot 0x576e108 relocates to 0x157b7f0. These are call-target observations; their complete behavior is unknown.

Direct calls in the body include 0x13e0220, 0x13df9d0, 0x14dab80 and unwind resume 0x5660110. Formatting and allocation helpers remain unresolved. `path preparation/sort` is an inferred label; the full caller contract, path enumeration, object layout, input ownership and helper closure are unknown. Next step: statically map 0x13e0220 and 0x13df9d0 before attempting a Rust API.

Task RE-001; component foundation. Static research only. Source revision 1f8c67c63ca4794c9689235471c60297f8a5c985; reference 999556f6e0a474b8312db96ec3149e1c44e97c23. Reference is inferred and unlicensed: no reference implementation was copied. New tools/tests/docs independently authored under repository MIT.

Target Linux x86-64 node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. All addresses are ELF virtual addresses, ends exclusive; file offsets and body digests are recorded in observed/records.json. No normalization. No captured binary execution. No Rust implementation/equivalence claim. All four foundation progress gates remain false. Comparison denominator is one FDE-validated research body; accepted raw-equal/normalized-only/unmatched reconstruction counts are unmeasured.

## Reproduce and controls

Tools: GNU objdump (GNU Binutils for Ubuntu) 2.42; GNU readelf (GNU Binutils for Ubuntu) 2.42; Python 3.12.3. GNU objdump -d with explicit start/stop addresses; GNU readelf -wf and -rW.

```sh
python3 tools/u_path_sort_static.py --output work/u-94
python3 tools/u_path_sort_static.py --output work/u-repeat-94
diff -r work/u-94 work/u-repeat-94
make doctor verify test catalogue-check reproduce
```

Full target digest/size is checked before analysis. Tests call lower-level validators on authentic bytes with individual instruction/literal flips and relocation retargets, bypassing the full-file hash so controls exercise their intended validators. Decoded objdump checks separately bind branch destinations, operand widths and raw tags/cutoffs. These static controls validate the packet, not runtime equivalence.

Before: no packet for this bounded body. After: one exact FDE, raw disassembly/FDE/RELA exports and independently reproducible digest-bound records. Initial verify failed because newly materialized local LFS reference retained stale index state; clean+local renormalization restored the unchanged pointer index. A separate optional git-lfs fsck --pointers crashed in local git-lfs and is not claimed as passing. No imports/pins were changed. Hosted CI/container/Ghidra were not run; doctor reports provider availability as observed.

Native checkout setup uses local LFS filters and locally ignores executable-mode differences from authenticated hardlinked artifact materialization; the committed artifact/index modes, bytes and reference revisions are unchanged. Working directory for all commands is the repository root; Linux x86-64, existing Python/GNU binutils and Git LFS required. No dependency install or global environment change.

Final validation: make doctor verify test catalogue-check reproduce returned 0 (initial full suite 436 tests); after the final Location corruption control, final make test returned 0 with 437 tests in 155.457s. Final targeted suite six tests passed. Repeated final producer exports are byte-identical. The final-test log is explicitly an excerpt; required-checks.log retains the complete earlier full-gate run.

After correcting only the tool module description, the final focused six tests passed and repeated producer exports were identical to the pre-correction exports. The full 437-test suite passed before this description-only correction.
