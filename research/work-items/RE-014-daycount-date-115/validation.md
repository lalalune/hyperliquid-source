Base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; Windows Python3.12.14, Capstone5.0.6.
Complete before:76 isolated files/373 reported tests;
after:77/379. Both retain23 failing
files,8 failures,18 errors,9 skips.
The exact FAIL/ERROR header multisets match. All six added tests, including the
actual compiler/corpus test, pass in the full run. The earlier installed focus
run passes five methods and explicitly skips the compiler method; separate
preflight already performed its real342074-input compiler comparison. That
skip is not counted as a compiler pass. Full runner wall:657.032s.
Required exits:doctor=1, verify=1, imports=1, packets=1, catalogue=0, reproduce=1, full-tests=1.
Catalogue passes; preexisting native/signature/import/LFS-packet problems remain.
No full-suite PASS, hosted CI or captured target execution is claimed.
Full after log SHA256:b546675f926f900d79be6cdd228e93c2b84686887b155c426db1a387db5c5270.
Actual Cargo offline/locked Linux-target release build passes. Direct-rustc
opt-level3 comparison flags/source/compiler identities are in rust-validation.json.
Implementation, comparator, native binder, retained proof and test source bytes
are unchanged from the full run; validation prose and manifest are finalized
subsequently. All unfinished component gates and byte-window metrics unchanged.
