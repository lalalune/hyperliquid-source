Exact base 8fd8db680ec4bfef40996e5616bce3d5156d0b86. Windows Python3.12.14/Capstone5.0.6.
Before 76 isolated files/373 reported tests;
after 77/379. Same 23 failing files,
8 failures/18 errors/9 skips;
exact identical FAIL/ERROR header multiset. All six new methods pass, including
actual compiler/corpus/controls. Focused run five passes/one explicit compiler
skip; actual preflight and full run separately exercise85203 comparisons.
Required exits: doctor=1, verify=1, imports=1, packets=1, catalogue=0, reproduce=1, full-tests=1.
Catalogue passes; existing GNU/GPG/import/LFS prerequisites remain failures.
No full-suite/hosted-CI success claim. Full after log SHA256 c8eae91a444ac631f75a4cc61b84d6906b4fe8e0520bc81486afb3cce82e2202.
Actual Cargo1.94.1 offline/locked Linux-target release build passes. This build
alone does not establish code identity. Direct-rustc flags and source/object
hashes are retained in rust-validation.json. Source/test/comparator/proof bytes
are frozen before the full sweep; only this prose and manifest finalized later.
No captured execution, byte-identity credit or component-gate advancement.
