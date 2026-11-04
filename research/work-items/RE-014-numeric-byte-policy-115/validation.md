Base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; Windows Python3.12.14/Capstone5.0.6.
Complete before:76 isolated files/373 reported tests;
after:77/379. Both retain23 failing
files,8 failures,18 errors,9 skips,
with exactly the same FAIL/ERROR header multisets. All six added methods pass
in the full run, including the explicit actual compiler/corpus/control method.
The earlier focused run has five passes/one explicit compiler skip; actual
compiler preflight separately completed266848 evaluations before installation.
The skip is not a compiler pass. Full runner wall:579.297s.
Required exits:doctor=1, verify=1, imports=1, packets=1, catalogue=0, reproduce=1, full-tests=1.
Catalogue passes; existing native/signature/import/LFS packet problems remain.
No full-suite PASS, hosted CI or captured execution claim.
Full after log SHA256:db7d643e7c81ebba247a1c28da3a4c05961458f8007fb86b57f1556e091e90aa.
Actual Cargo offline/locked Linux-target release build passes. The direct-rustc
opt-level3 probe comparison has explicit no-vectorization flags retained in the
record; Cargo build alone is not a Cargo-object identity claim. Source,
comparator, native oracle, tests and retained compiler proof bytes are unchanged
from the full run. Validation prose/manifest are finalized afterward.
All component gates and byte-window metrics remain unchanged.
