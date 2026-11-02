# Completed host validation

The initial environment failures in README.md are retained as historical
observations. The missing research tools and pinned inputs were subsequently
materialized locally; no captured executable was run.

- `make doctor`: analysis ready. This does not mean an exact full-node rebuild
  is ready; Java/Ghidra are optional and unused here.
- `make verify`: pass. All eight artifact sizes/SHA-256 values, all three
  executable signatures, pinned binary/key/signature pairs, 38 imported files
  and all source pins match.
- `make reproduce`: pass. Inventories, raw counts and refined item
  classifications reproduce the imported evidence.
- `make catalogue-check`: pass; no progress gate or byte registry is changed.
- Complete pre-existing flat unittest inventory: **971/971 files pass**,
  zero failed files, 15,468 reported test cases and 72 skip records. No test
  file was excluded or modified. `validation-results.json` retains per-file
  exit status, counts and local-log digest.
- The inventory used six workers, each invoking the repository runner's same
  isolated `python -B -m unittest discover -s tests -p <file> -v` command in a
  fresh process. Total elapsed time was 1,300.602 seconds. This changes only
  scheduling of the existing per-file subprocesses, not discovery or assertions.
- The final formatted production source and harness were revalidated with the
  explicit rustc 1.94.1 binary: all three 25,135-case comparisons, own unit tests,
  eight compiled mutants and repeated optimized-library hashes pass. Updated
  source/build digests are in `results.json`. `rustfmt --check` passes.

Environment: macOS arm64, Python 3.14.5 / Capstone 5.0.7 for the full inventory;
GNU binutils 2.45 built with x86-64 ELF support; LLVM tools 23.1.4; GnuPG 2.5.24;
Git LFS 3.8.1; Node 24.22.1; rustc 1.94.1 and 1.95.0. Focused final compilation
uses rustc 1.94.1, edition 2021, warnings denied and overflow checks enabled.

The checkout is based on main
`e5c9b6436876b2a4a39daef813171f9879317699`, with this independent module/packet
present. Shared production tools and existing tests are unchanged. The separately
submitted JSON-tail, RPC-code and checkpoint modules are independent branches;
this result is not described as a separate full-suite run on each of their heads.

These are author-observed checks, not independent peer review, hosted CI,
original-node execution, machine-code identity, Docker/network acceptance or
full-component recovery. The original negative run remains incomplete and is
not counted as a passing run. No optional traces or usage logs were uploaded.
