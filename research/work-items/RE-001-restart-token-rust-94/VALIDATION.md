# Validation scope

- Base main: `e5c9b6436876b2a4a39daef813171f9879317699`.
- `make doctor verify catalogue-check reproduce`: pass in this checkout. All
  eight artifact hashes/sizes, three executable signatures, 38 imported files
  and pinned source revisions match; generated progress remains unchanged.
- Existing relevant static controls: 6 tests pass without skips.
- Independent new Rust: rustc 1.94.1, edition 2021, warnings denied and overflow
  checks enabled; debug/optimized/repeated optimized builds each agree with
  all 21,233 frozen scalar expectations. All 5 compiled semantic
  mutations are detected with normal process exit. Own unit tests and
  `rustfmt --check` pass; repeated optimized library digests agree.
- Full flat 971-file inventory: running in the separate shared validation
  checkout. No completed full-suite result is claimed at this revision.

`validation-inputs.json` fingerprints the byte-identical tracked tools, tests,
provenance, config and scope registries shared by the three independent branches.
Each new source/harness is compiled and compared separately; these modules have
no root workspace or existing-test integration. A shared baseline result will
not be described as a separate full-suite run on every PR head.

Environment: macOS arm64; Python 3.14.5 / Capstone 5.0.7; GNU binutils 2.45
with x86-64 ELF support; LLVM disassembler 23.1.4; GnuPG 2.5.24; Git LFS
3.8.1; Node 24.22.1; rustc 1.94.1. The static decoders read captured input
bytes; only the independently built host Rust code is executed.

These are author-observed checks. Hosted CI, independent review, original-node
execution, original ABI, full helper/effect closure, code identity, integrated
node acceptance and completed progress gates are not established.
