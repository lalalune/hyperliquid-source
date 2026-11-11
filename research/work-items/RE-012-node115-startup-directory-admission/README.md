# Startup directory and non-directory admission

Partial evidence and an independently authored offline adapter for
[issue #3927](https://github.com/lalalune/hyperliquid-source/issues/3927).
This work binds the two startup wrappers to their different path-admission
views. It does not close a startup, storage, or replay component gate.

## Artifact and method

Original node #115 ELF: `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The packet retains 16 selected instruction windows, 2,795 bytes and 689
instructions, plus a 256-byte UTF-8 width table. It checks 83 explicit facts
and rejects 15 semantic corruptions after bypassing whole-image/window hash
comparisons. Those counts include prerequisites; they are not counts of
newly discovered functions or full component coverage.

Capstone 5.0.7 decodes from each enclosing FDE boundary. `verify.py` authenticates
the whole original ELF, each selected window and instruction row, call targets,
relocations, the imported `opendir` identity, and the selected branch/field
facts. Controls change wrapper targets, error tags, mode/flag fields, filter
polarity and UTF-8 lead-byte classification. No target code is run or emulated.

## Bound path

| Stage | Static observation |
| --- | --- |
| Startup first call | `0x595b553` resolves through `0x64e0968` to `0x1501290`, using the original path pointer/length. |
| First wrapper | Calls `0x5c9ca30` through `0x64e0970`. Byte tag 2 goes through error translation `0x14cc980` and returns outer tag 1. Otherwise it calls the common collector `0x15b5b00`, then `0x15b58c0`, and returns outer tag 0. |
| Directory filter | `0x15b5902` calls `0x153f470`. Its first and subsequent row loops retain bit 0 at row offset `0x18` when set and emit the first three words into 24-byte rows. |
| Nested startup call | `0x595b698/69c` obtains the selected first-stage row's path pointer/length; `0x595b6a5` resolves through `0x64e09d0` to `0x15021d0`. This packet does not reimplement the intervening container selection. |
| Nested wrapper | Shares the opener/error translation/common collector, then calls `0x15b59e0`, which calls `0x1540a40`. |
| Non-directory filter | `0x1540aa8` and `0x1540c10` compare row offset `0x18` with 1 and retain the unequal case. The mapper supplies only 0 or 1, so this is the complement of the first view under valid provenance. |

The opener contains the imported `opendir` call at `0x5c9cb83`; no live open is
performed by this contribution. Native error translation remains an explicit
opaque boundary in the source API.

The shared, previously mapped entry mapper `0x150bad0` suppresses entry errors
with the `0x8000000000000000` sentinel. Metadata result tag 2 sets its directory
flag to 0; otherwise it computes `(mode & 0xf000) == 0x4000`. A failed text
conversion also produces the sentinel. A successful conversion is copied to
an owned path triple with that flag at offset `0x18`. The common collector
skips the sentinel in both its first and later entry loops.

The text helper is relocation-bound to `0x16815e0`. Its lead-byte width table
and 503-byte FDE implement the observed UTF-8 byte classes and continuation,
overlong, surrogate and upper-codepoint restrictions. Success returns original
pointer/length with tag 0; failure returns tag 1. The owned adapter uses Rust's
`str::from_utf8`; its offline tests exercise representative valid and invalid
classes without claiming exhaustive native execution equivalence.

Consequently, **metadata failure is not entry failure**: with valid text it is
excluded from the directory view and included in the non-directory view. No
regular-file requirement, freshness guarantee or successful checkpoint read
follows from that inclusion.

## Prior work and overlap

`RE-017-abci-prune-path-115` already maps `0x150bad0`, including its metadata
flag, text failure sentinel, and a later flag-1 exclusion. Those mapper facts
are credited prerequisites and retained here to validate the new source.
`RE-017-entry-checkpoint-115` already maps the shared collector and nested
24-byte producer; its internal container/selection work is not re-claimed.
[PR #3319](https://github.com/lalalune/hyperliquid-source/pull/3319) covers the
outer startup selector window. This contribution adds the paired wrapper to
filter binding and an offline admission API across those boundaries.

Terra checked current main and the complete 391-open-PR inventory, relevant
open patches, and targeted all-state title/body searches for the wrappers,
mapper/filter addresses and startup-directory semantics. No competing owned
admission adapter was found. Historical title/body searches do not prove that
every unindexed closed patch was inspected. Reused evidence is identified
above rather than described as novel.

## Reproduce and limits

```sh
python3 research/work-items/RE-012-node115-startup-directory-admission/verify.py
cargo test --offline --manifest-path src/node115-startup-admission/Cargo.toml
cargo test --offline --release --manifest-path src/node115-startup-admission/Cargo.toml
```

Python requires the repository's audited ELF helper and Capstone 5.0.7.
`verification.json` records the successful original-artifact check and all
15 rejected controls. Eight owned-source integration tests pass in each Rust
profile; see [source documentation](../../../src/node115-startup-admission/README.md).

Valid native records and normal helper returns are premises. Path joining,
filesystem contents, native sort/dedup/container behavior, allocation failures,
unwinding, native error ABI, later suffix/checkpoint policy, and persistence
are not proved. The adapter's encounter-order `Vec` is an explicit host API
choice. Component gates and shared implementation claims remain unchanged.
