# Reconstruct the EVM archive member and path plan

The checkpoint archive consumer needs a way to go from dated status files and provider heights to reproducible archive member names and endpoints. The [prior archive packet](../RE-001-node115-evm-archive-checkpoint-intersection/README.md) established exact decimal membership on supplied names. This contribution connects that contract to a real Unix fixture, binds the archive owner's basename conversion and both complete filename templates, and adds a read-only Rust adapter.

**Target.** Linux x86-64 node 115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`. The addresses below are ELF virtual addresses. The verifier reads the captured bytes as data.

| Producer or consumer | Observed behavior |
| --- | --- |
| Owner `0x38c40f0`, date input in EDX | Templates at `0x448b77` and `0x43aa84` join the root, the RELATIVE string descriptor at `0x646ea00` and the displayed date. They yield `{root}/data/periodic_abci_state_statuses/{date}`. The date formatter at `0x150ce90` uses `%Y%m%d`. |
| Directory admission | `0x38c41ec` checks the directory; the false path formats the error at `0x44db85`. The true path calls `0x15021d0` at `0x38c4205`. Its non-directory view retains valid path text with a false directory flag, including a metadata failure. See the [shared startup mapper and its exclusion rules](../RE-012-node115-startup-directory-admission/README.md). |
| Full path to set key | The owner calls `0x15b54d0 → 0x153f7b0 → 0x155ca60`. The last routine walks the reverse path component (slot `0x64e0938`), checks normal-component tag 9 at `0x155cb5d`, validates UTF-8, and copies the component bytes. Its fallback uses the original path pointer and length. Entries returned by a successful Unix directory listing have normal final names, and the shared admission step has already checked the full text. |
| Filter and member order | `0x38c42bb` calls the checkpoint provider. After the sort dispatch, `0x38c4361` filters against the name set. The Rust API accepts heights at that post-sort boundary. The [prior intersection](../RE-001-node115-evm-archive-checkpoint-intersection/README.md) supplies the exact decimal comparison, selected order and projection to member arguments. This permits duplicate provider rows. |
| Temporary filename | `0x38c4379` skips the path for an empty result. Otherwise the owner reads the first and last retained row's u64 at offset 24. It calls `0x1564620` and formats all three numbers using slot `0x64e0a98` and template `0x44e8bf`: `/tmp/evm_state_checkpoints_{first}_{last}_{id}.tar`. The callback supplies the third number. Its origin and uniqueness are separate questions. |
| Final filename | `0x38c4478` and the four argument slots select `{root}/data/daily_evm_checkpoints/{date}/{first}_{last}.tar`. The regular-file check at `0x38c44b5` precedes member argument preparation. A file suppresses archive construction. A directory at that path passes through the false branch. |

**Prior work and limits.** [#2909](https://github.com/lalalune/hyperliquid-source/pull/2909) excludes directory traversal and path formatting. [#5999](https://github.com/lalalune/hyperliquid-source/pull/5999) and [#6001](https://github.com/lalalune/hyperliquid-source/pull/6001) cover related snapshot paths. The [periodic-state producer](../RE-008-periodic-state-path-115/README.md) supplies the date display contract. This consumer requires canonical status filenames even when the provider already has a valid numeric height. The checkpoint restore path and its marker policy are independent. The adapter leaves checkpoint discovery and sorting, date production, diagnostic and error ABI, filesystem races, shell/tar behavior, publication and pruning outside its interface. No component gate changes.

Terra checked current main, all-state GitHub searches for the archive owner, selection helpers, filenames and archive/checkpoint wording, and the earlier static work. Title/body searches can miss contents of unindexed patches. All implementation and fixtures are independently authored. The verifier uses the repository's ELF/unwind readers and existing packed-format decoder.

## Reproduction

From the repository root, with the active target materialized:

```sh
python3 research/work-items/RE-011-node115-evm-archive-plan/verify.py
cargo test --locked --offline --manifest-path src/node115-evm-archive-plan/Cargo.toml
cargo test --locked --offline --release --manifest-path src/node115-evm-archive-plan/Cargo.toml
cargo clippy --locked --offline --all-targets --manifest-path src/node115-evm-archive-plan/Cargo.toml -- -D warnings
```

The verifier authenticates ten FDEs and 67 instruction starts, resolves six direct and nine indirect calls, rejects nine shifted displacement controls, and decodes the five selected format descriptors at their owner use sites. Four Rust integration tests cover real status entries, a missing directory, an empty intersection, aliases, duplicates, a dangling link, unsigned maximum, lexical root separators, the regular-file versus directory check, and temporary-ID timing. Only the source-built adapter runs on the host.
