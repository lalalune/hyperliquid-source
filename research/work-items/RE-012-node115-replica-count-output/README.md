# Interpret child output for the replica line count

Given the outcome of an ordinary local `wc -l` invocation, `src/node115-replica-line-count` returns the selected unsigned count or the failure class at the stage where processing stopped. This connects observed child termination, whole-output UTF-8 admission and decimal parsing for a startup input. A valid first count followed by invalid UTF-8 fails. Valid trailing filename text does not affect the result.

**Target and scope.** Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, source base `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`. All addresses are ELF virtual addresses. The existing [line-count study](../RE-001-startup-line-count-115/README.md), [output adapter](../RE-001-startup-shell-output-115/README.md) and [UTF-8 validator](../RE-001-startup-utf8-result-115/README.md) establish the native boundaries. [PR #7077](https://github.com/lalalune/hyperliquid-source/pull/7077) calculates the count from LF bytes in a supplied file. A child producing text or returning an error is a different input to startup.

| Stage | Selected evidence and observable result |
| --- | --- |
| Child outcome | `0x595bb9c` binds the replica-height caller to `0x1500e50`. At `0x1500f1a` the count routine calls adapter `0x1536720`. Its launch-result sentinel and subsequent status test at `0x1536823` precede parsing. A failed command cannot contribute its output count. |
| Text validation | On the zero-status arm, `0x15368b7` calls `0x16815e0` with the selected buffer and length. The failure tag at `0x15368cd` applies to the whole buffer. On the ordinary host adapter the selected stream is represented by stdout. The Rust error exposes failure position and any known invalid-sequence length. |
| First field | The scanner skips leading whitespace and consumes the first nonempty token. Its ASCII mask at `0x1500f46`, table bits and explicit exceptions together admit 25 Unicode whitespace scalars. Whitespace-only output has a distinct error path. An invalid first token does not cause a retry at a later token. |
| Decimal parse | One leading ASCII plus is admitted; a lone sign fails. At 17 or more digits the checked multiply and add can separately reject overflow. Successful zero takes the normal return tag. `u64::from_str` supplies the corresponding logical result. |

The API takes an existing host `io::Result<Output>` and performs no process launch. Native spawn protocol, shell construction, diagnostic strings, allocator failures and the compressed-file prelude stay outside the claim. The focused tests launch the host's ordinary `wc` with separate arguments on disposable input and on a named temporary file. They never run the captured node.

## Reproduce

```sh
python3 research/work-items/RE-012-node115-replica-count-output/verify.py
cargo test --offline --locked --manifest-path src/node115-replica-line-count/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-replica-line-count/Cargo.toml
cargo clippy --offline --locked --all-targets --manifest-path src/node115-replica-line-count/Cargo.toml -- -D warnings
```

The static verifier checks three complete FDE identities, 33 instruction witnesses, three relative call bindings and three intentionally shifted slots. It reconstructs the delimiter set from the mask, two bit planes and page exceptions. The Rust suite compares this set to the host predicate over every Unicode scalar, checks invalid UTF-8 after a count, status precedence, numeric overflow, empty versus zero, and confirms the parse against real `wc` output. Only the active target is read, using the existing standard-library ELF readers. GNU objdump supplied instruction boundaries and spellings.
