# Validation status

Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Host: macOS arm64, Python 3.14.3, rustc 1.94.1; actual compiler binary hash
and reported commit are checked. Linker identity is recorded separately.

- `make doctor verify catalogue-check reproduce`: exit 0 in this worktree,
  with GNU binutils PATH and LLVM_OBJDUMP=/usr/bin/objdump. All target
  signatures/digests, 38 imports and pinned repositories verify.
- `verify_static.py`: exit 0, including five structural corruptions.
- Initial and final `python3 -O -B verify_rust.py`: exit 0. Final changes
  deduplicate raw streams and replace the actual compiler path with a label;
  numerical results and all mutation counts are unchanged.
- 137,000 frozen rows match at opt0/opt3 and both repeats; two unit tests
  pass at each optimization. Repeat libraries, clients and outputs are raw equal.
- Eight compiled wrong variants are rejected by observed result differences.
- All final lossless raw archive payloads match retained byte counts/hashes.
- Independent read-only review found no blocking arithmetic/domain error,
  confirmed the half-boundary and large-value arguments, and reproduced
  the static verifier. No original code was run.

The shared 971-file `make test` sweep is running in the coordinating checkout
on this exact baseline plus additive ceil Rust packet #1382. This component
adds no root tooling or test files and its explicit checks ran separately.
No completed full-suite, hosted CI, container or original x86-64 byte match
is claimed. All component gates and byte-window counters remain unchanged.
