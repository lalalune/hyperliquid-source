# RE-002: distinguish frame-pointer profiles for five node #115 core formatters

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Baseline 2da45cb0a761cff6b478e40421699857d87a94df. Rust source 1.95.0 commit 59807616e1fa2540724bfbac14d7976d7e4a3860 with rust-src archive SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The published standard library census already supplies the target windows. Two fresh source builds keep the compiler, source, target and opt-level 3 profile fixed and vary only the explicit rustc frame-pointer flag. With `no`, none of the five bodies has the recorded target extent. With `yes`, all five extents agree and the 84-byte `write_prefix` body at 0x1686260 matches raw, with no relocation in its source section. The other four equal extents remain unequal byte comparisons and are not counted as equivalent. This identifies a reproducing setting for one leaf and a discriminating extent setting for the selected cohort. The original node-wide setting remains unknown.

Provision the cache using RE-002-node115-umodti3-source-build. Run from the root with Python 3.12+, Rust and Cargo 1.95.0, and GNU binutils 2.42 or equivalent:

```sh
python3 -B research/work-items/RE-002-node115-core-frame-profile/verify.py /path/to/cache /path/to/binutils
```

The supplied binutils directory must expose ar, nm-new, objcopy and objdump. If necessary, point nm-new at the installed GNU nm. The log records the exact counters and VAs. The capture is only read as bytes and no acceptance gate changes.
