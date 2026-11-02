# Rust validation scope

The completed author run passed **139 commands**, with all exits zero. In each of debug and release, **44,679 value cases**, **211 integer length cases** and **six handwritten tests** passed; all **14 compiling semantic mutants** were detected, and all **ten comparator corruptions** were rejected. The fresh same-path rebuild's own rlib and client were raw-equal in both profiles. Every one of the **278 raw stdout/stderr references** was independently decompressed and rehashed after copying receipts into the packet. `AUTHOR-RUN.json` records that verification. No source or frozen harness amendment was needed.

| Compiled change | Different value rows per profile | Different length rows per profile |
| --- | ---: | ---: |
| Trim retained input | 3,591 | 0 |
| Retain blank input | 17,982 | 0 |
| Accept NUL | 641 | 0 |
| Change leading-caret mode | 2,645 | 0 |
| Swap quote priority | 13,894 | 0 |
| Consume conflict byte early | 6,969 | 0 |
| Omit double-quote escapes | 4,828 | 0 |
| Reverse operands | 25,928 | 0 |
| Change separator | 43,952 | 0 |
| Return option zero | 44,038 | 0 |
| Replace U+0085 membership | 7 | 0 |
| Replace raw plus admission | 788 | 0 |
| Reject exact length bound | 0 | 20 |
| Wrap length addition | 0 | 29 |

The debug and release mismatch counts agree. These are actual output differences after successful compilation, not source-identity rejections.

The real package is `src/visor-move-request`, a standalone dependency-free Cargo library with an actual Cargo-generated lockfile. It is not a root workspace, supervisor skeleton or borrowed unlicensed implementation. The original static `MANIFEST.json`/`AUTHOR-FREEZE.json` and independent `pre-rust/PRE-RUST-FREEZE.json` are unchanged. `SOURCE-FREEZE.json` fixes all production files and the client, driver and bridge before the first production compilation.

`build.py` reads only the newly authored source, frozen value inputs/expectations and their integrity records. It does not execute, emulate or evaluate captured instructions and does not call a shell, a move operation, preflight or network. It uses the installed, content-pinned Rust 1.94.1 aarch64-apple-darwin Cargo/rustc/rustdoc, inspects the real manifest/lock and exact source file set, and checks Cargo metadata for one package with no dependency/build-script/proc-macro target. This host is not the original Linux x86-64 Visor compiler.

The build copy and Cargo home are fresh isolated directories under `/tmp`; `CARGO_NET_OFFLINE`, explicit `--offline --locked`, no inherited Rust wrappers/flags, and an explicit clean environment prevent ambient Cargo/user configuration from entering the declared build. Original HOME is left unchanged and is not read or published. The driver checks lexical ancestor Cargo config absence, while `CANONICAL-ANCESTOR-AUDIT.json` additionally records actual `/private` and `/private/tmp` checks because macOS canonicalizes `/tmp`. This is a configuration audit, not an OS sandbox or a proof that host files are inaccessible. The standard toolchain `bin`/`lib` payload inventory, selected clang/ld/xcrun/ar identities, SDK settings and libSystem import stub are hashed before and after; the whole OS, dynamic loader and SDK are not claimed hermetic.

The driver performs offline locked Cargo library builds and six handwritten tests in both debug and release. A separately compiled client links each **actual Cargo-produced rlib** through `--extern`; only input TSV is supplied on stdin. The client has no expected-file lookup, expected status, output hash or answer argument. The Python parent independently reads expected bytes, compares full raw stdout, and refuses differences in status, option, payload, row order, row count or newline. Allocation failure is reported distinctly and is not treated as a target-grounded expected result. No forced OOM or unsafe giant slices are constructed.

Expected values were frozen before Rust. They come from a distinct longest-prefix-per-language mathematical oracle bound to captured constants and the manually reviewed six-body proof, not from captured runtime observations. The 44,679 UTF-8 input pairs include 44,038 success and 641 NUL cases; 211 integer-only length pairs cover the sufficient domain and addition overflow. Finite agreement supports the all-input bridge; it cannot prove target equivalence on its own.

After the baseline run, the driver moves aside the first target tree and rebuilds into a fresh target tree at the same isolated path. It compares complete own rlib and own client bytes, without masks or normalization. This is repeatability of this authored host build in that environment, not target machine-code equality or cross-directory/toolchain reproducibility.

Fourteen individual production mutations are made only in the private build copy: trimming retained inputs, retaining blanks, accepting NUL, changing the leading-caret mode, swapping quote priority, consuming the conflicting byte early, omitting double-quote backslash insertion, reversing operands, changing the separator, returning option 0, replacing U+0085 membership, changing raw `+` admission, excluding the exact length boundary, and wrapping the length addition. Each mutant must compile and run in **both** profiles and differ from frozen expected output. Tests are not run on these deliberately wrong variants; compile failure is not counted as sensitivity. Actual commands, exit codes, complete output streams and row-level mismatch counts establish which error was observed.

The exact comparator also rejects ten output corruptions: missing/extra/reordered rows, duplicated ID, wrong option/status/payload, missing final newline, empty stdout and CRLF. These are comparison-integrity controls, separately distinguished from compiling semantic mutants. Source/pin checks likewise are integrity controls and not a substitute for the actual output comparisons.

Reproduce from the repository root, using fresh output and private-map paths:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-013-visor-move-argument-encoding/rust-validation/build.py \
  --toolchain /path/to/1.94.1-aarch64-apple-darwin \
  --out /tmp/visor-move-reproduction \
  --private-map /path/outside/public/visor-move-private-map.json
```

The exact pinned tool hashes are in `build.py`. The private map records physical source/toolchain/build/packet paths; it must stay outside publication. Public commands and identities use `<BUILD>`, `<TOOLCHAIN>`, `<SOURCE>` and `<PACKET>`. Raw logs are unmodified; their disposable `/tmp` paths and public system paths are retained, while the driver rejects accidental original-HOME text. The mapping preserves reproducibility without publishing private workspace paths.

`receipts/commands.json` records every invoked build/version/client command and every raw stdin/stdout/stderr hash, byte count and stream reference. Raw streams are gzip-compressed and content-addressed, so identical empty logs and profile outputs are stored once. If an actual output exactly equals a frozen stream, its reference points to the existing `pre-rust/frozen` gzip; no repeated copy is needed. `receipts/results.json` records the actual result and own-build comparisons; `receipts/build-audit.json`, `compile-environment.json` and `toolchain-files.json` retain the graph/config/tool identities. Full expectation streams never enter the client.

Residual limits are the original explicit native preflight/storage/callee/allocator premises; the new safe API's chosen length/NUL check order and host allocation policy; finite test coverage; opaque target error values; and absence of target ABI/runtime, allocator parity, shell/FS effects, original compiled-byte match or full component completion. The library and client contain no unsafe Rust. Host compiler/standard-library correctness remains a build trust assumption.
