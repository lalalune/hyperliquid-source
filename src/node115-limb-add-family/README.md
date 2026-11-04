# Node115 whole addition-leaf family

Independent dependency-free no_std safe arithmetic and final-state API.
add_with_carry mutates four left limbs and returns a copy plus unsigned carry.
guarded_add qualifies count against safe storage, returns raw44 without changes
for0/1, otherwise folds the final entry into its predecessor and lowers count.
Its CountOutsideStorage refusal is new safe API policy, not a native error.
No native ABI, alias/fault/concurrency, symbol/type, owner or protocol claim.

Original whole FDEs298f5b0,29fc880,4fb12f0 and the input-only fixture adapter
are in research/work-items/RE-004-limb-add-family-115. Two carry bodies are
identical aliases, not separate contributions. Expectations were committed at
2311463613149d7f590895dacd6de1087e863ee8 before new Rust existed. Build with
the packet's build.py and actual rustc1.94.1/edition2021; no invented Cargo graph.
