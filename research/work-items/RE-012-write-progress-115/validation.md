Exact tested base: 8fd8db680ec4bfef40996e5616bce3d5156d0b86. Windows Python3.12.14 / Capstone5.0.6.
Complete before: 76 isolated files / 373 reported tests;
after: 77 / 379. Both retain 23 failing
files, 8 failures, 18 errors and 9 skips;
the complete FAIL/ERROR header multisets match. All six added tests pass in the
full run. Required exits: doctor=1, verify=1, imports=1, packets=1, catalogue=0, reproduce=1, full-tests=1.
Catalogue passes. Native/GPG/import/LFS packet prerequisites remain failing;
this is NOT a full-suite pass, native execution or hosted CI success.
Full after log SHA256: 1a45844a871da441c6d4cee64c5e8a8441b238961c9151f75ab18854958b2413.

After the full sweep, line endings only were canonicalized in Cargo.toml,
the test EOF and packet prose. Rust implementation and comparator byte hashes
are unchanged; Python AST and parsed TOML remain identical. Actual compiler
proof, original exports, six compiled mutants and four operative target
counterexamples were regenerated on the final files; all six focused tests
pass again (controls.txt). The full sweep was not repeated after that textual
normalization. Cargo offline/locked Linux-target release library build passes.
Only own compiled probe code is interpreted. No captured target is executed.

Cargo default release opt-level3 is a separate build check. Measured own-code
comparisons use the explicit direct-rustc opt-level2 profile in rust-validation.json;
no Cargo object identity is claimed.
The charge API returns a numeric wrapping sum only; atomic memory ordering,
shared-counter interference and live counter publication are not reconstructed.

Disassembly display trailing spaces were removed after qualification; all
instruction bytes, instruction counts and body hashes remain unchanged.
