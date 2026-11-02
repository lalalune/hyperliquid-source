# Validation

- `make doctor`: passed after selecting the already installed GNU binutils.
  Reports static analysis ready and exact rebuild not ready.
- `make verify`: passed. All captured artifact sizes, SHA-256 values and
  signatures match; 38 imported files and all source pins match.
- `make reproduce`: passed. Both inventories and the imported literal
  classifications reproduce without changing imported evidence.
- Independent GNU `readelf --wide --section-headers` output agrees with the
  catalogue's code, allocated-data and zero-fill counts for all three targets.
- Focused byte-accounting tests: 17 passed. Catalogue/research tests: 50 passed.
- Full offline test-file inventory: **957/957 files passed after environment
  retries**; 15,230 reported test cases, including 71 skips. The primary run
  passed 954 files. The Capstone test then passed under existing Python
  3.13.2 / Capstone 5.0.7; two dual-disassembler tests passed after adding the
  installed LLVM 22.1.4 to PATH. Other tests used Python 3.14.6. No remaining
  failures. See [machine-readable results](validation-results.json).
- The sequential `make test` run was interrupted and replaced with six
  workers, each launching the same isolated `unittest discover` invocation
  per file. No test was excluded or changed by the runner. The initial
  parallel attempt also lacked GNU tools on PATH and was restarted; it is
  not counted as a passing run. Transient commands and per-file logs remain
  under ignored `work/node-scope-accounting/`.
- `make catalogue-check` and `git diff --check`: passed.
- Captured node/visor execution, full-node build, Docker runtime and network
  acceptance: not performed; no corresponding success is claimed.

The Docker CLI is installed but its daemon socket is unavailable. Starting a
daemon would not supply the missing integrated node implementation. The
existing development image is not a source-built node runtime image.
