# Ending height from a local replica directory

`src/node115-replica-end-height` implements the local file selection and ending-height computation used by startup. A caller supplies a replica directory root. The implementation uses the [existing listing admission](../../../src/node115-startup-admission/) and [reverse path component reader](../../../src/node115-reverse-path-components/). The [last-height packet](../RE-008-replica-cmds-last-height-115/README.md), [line-count packet](../RE-001-startup-line-count-115/README.md), [file-height composition](../RE-001-node115-startup-file-height-composition/README.md) and [end-height window PR](https://github.com/lalalune/hyperliquid-source/pull/3319) are prior evidence.

Target `artifacts/node/115/hl-node` has 105896032 bytes and SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Startup selection

At `0x595b2b9` the owner sets a five-entry limit, then calls `0x5accff0`; the collector at `0x543db40..0x543db6f` takes each path from the back of the ordered directory tree, calls the per-directory reader and appends its tag and value. The limit counts attempted directories. Afterwards `0x595b2f0..0x595b3da` skips errors and computes the unsigned maximum of successfully returned heights, including zero. A folder outside the window cannot replace a rejected attempt. An empty or wholly unsuccessful window has its own error.

The per-directory reader at `0x595b520` selects the lexically greatest date directory via the tree's rightmost leaf. It walks nondirectory entries backwards and skips exactly the case-sensitive suffix `.lz4` before committing to a file. It does not try earlier files after a bad selected numeric filename. At `0x595ba57` the final normal path component is requested and validated as UTF-8. The selected text is parsed as unsigned decimal, including the optional leading plus. The count helper receives the original full path at `0x595bb9c`; a successful count is added with saturation. Native `0x1500e50` supplies the arguments `wc` and `-l`. On stable local regular files the crate obtains the same LF count with a buffered Rust reader. Payload bytes need not be UTF-8 and a trailing partial record contributes no line.

The host adapter opens a supplied Unix directory, admits UTF-8 paths by the existing listing rules, and computes the logical result for ordinary directories and regular files. Native child-process spawning and diagnostic formatting, symlinks and special files, race or concurrent mutation behavior, and full replay startup remain outside the equivalence claim.

## Reproduction

```sh
python3 research/work-items/RE-012-node115-replica-end-height-source/verify.py --target artifacts/node/115/hl-node
cargo test --offline --manifest-path src/node115-replica-end-height/Cargo.toml
```

Capstone 5.0.7 and pyelftools check the digest, FDEs, original instruction and literal bytes, and the indirect helper bindings. The Rust integration tests build disposable directories with real files. They distinguish lexical from numeric ordering, failed attempts from successful heights, literal suffix matching from case-insensitive filtering, LF counts from logical records, and saturation from wrapping. A 9,001-line input crosses the read buffer boundary. The tests do not launch the captured program or a shell.
