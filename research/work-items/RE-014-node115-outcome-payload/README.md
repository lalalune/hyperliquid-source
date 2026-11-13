# Outcome payload fields on node #115

This advances backlog **HL115-088** from the enum-entry boundary to the two
JSON struct payloads. It does not complete the risk component or establish an
outcome-record/state join.

Target: node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Original ELF disassembly and relocation inspection only; the captured program
was neither executed nor emulated.

## Prior work and new scope

[#3388](https://github.com/lalalune/hyperliquid-source/pull/3388) reconstructs
outcome-name leaves. [#5088](https://github.com/lalalune/hyperliquid-source/pull/5088)
corrects the unit-enum inference and identifies the struct-payload calls,
explicitly leaving their readers unclosed. This contribution begins at
`0x1e0c420` and `0x1e07570` and uses the original calls at `0x25d8de1` and
`0x25d8e18` only to bind the returned payload to that existing entry.
[#4325](https://github.com/lalalune/hyperliquid-source/pull/4325) and
[#4588](https://github.com/lalalune/hyperliquid-source/pull/4588) concern a
separate five-field record writer; no join to it is inferred here.
The strict byte-string scanner comes from
[#5576](https://github.com/lalalune/hyperliquid-source/pull/5576), imported
unchanged by the source reader. It is not counted as new discovery.

## Recovered contract

| Payload | Object form | Sequence form | Returned representation |
| --- | --- | --- | --- |
| StandaloneOutcome | `{"side_names":["yes","no"]}` | `[["yes","no"]]` | Two 24-byte string descriptors, 48 bytes total |
| QuestionOutcome | `{"parent":"question-1"}` | `["question-1"]` | `0x8000000000000001`, followed by one 24-byte string descriptor |

`side_names` is a fixed **two-string array**. Its `0x1e41440` reader invokes
the string reader twice, diagnoses zero/one items with actual length 0/1, and
then checks the closing bracket. A third item fails; a comma followed by `]`
has a distinct error code (21 versus 22). Both outer sequence forms require
one payload field.

The key scanner decodes escapes before comparing the exact field bytes, so
`par\u0065nt` is the same recognized key as `parent`. Missing fields fail.
A recognized duplicate fails **before checking/consuming its colon** or
reading its value. End-container cleanup still runs and can consume a closing
delimiter or whitespace; the original duplicate/value error wins over a later
end-check error. Native branches and source fixtures cover this precedence.

`0x1e41b20` copies the strict scanner's returned byte span into a string
allocation with capacity and length equal to that span's length. The source
uses `Vec<u8>` so it does not add raw UTF-8 validation absent from the recovered
scanner.

The parser uses only space, tab, CR and LF as whitespace. Container entry
debits depth before consuming the opening delimiter; a debit to zero returns
code 24 without restoring that failed entry. Completed container visits restore
one depth unit before their end check. Zero initial depth reaches a checked
underflow assertion and is an explicit boundary in the source.

`0x25d8f18..0x25d8f32` copies the payload's 48-byte enum representation to the
direct caller's output after the outer `}` check. This closes that immediate
handoff, not the identity of a stored parent, owning application state, or
settlement semantics. Unused bytes in QuestionOutcome are not promoted to
initialized semantic fields.

## Domain and boundaries

The source covers recognized fields in both object/sequence payloads,
structural errors and scanner errors. It stops before the unknown-value skip
helper (`0x1d75560`) and type-error visitor (`0x1d76fd0`). A stop is a suspended
call with cursor/depth at that boundary, not a native rejection or successful
skip. This is not a complete generic JSON parser. Allocation, formatted
diagnostics/error positions, panic unwinding, sibling readers
`0x3f96950`/`0x3fa9340`, and the wider state join remain outside this contribution.
The backlog item and full-scope component gates stay open.

## Reproduction and validation

With Capstone 5.0.7 and pyelftools 0.32 available:

```sh
python3 research/work-items/RE-014-node115-outcome-payload/verify.py --target /path/to/original/hl-node
cargo test --offline --manifest-path src/node115-outcome-payload/Cargo.toml
cargo test --offline --release --manifest-path src/node115-outcome-payload/Cargo.toml
cargo clippy --offline --manifest-path src/node115-outcome-payload/Cargo.toml -- -D warnings
```

`records.json` binds ten original windows (6,721 bytes / 1,554 instructions),
59 semantic facts and 44 in-memory corruption controls to the target digest.
Controls change key length/bytes, cardinality branches, depth operations,
output layout, separator/error codes or the scanner relocation. These are
static evidence checks, not runtime differential tests. Rust fixtures exercise
both forms, escaped-key duplicates, missing/cardinality errors, trailing commas,
raw byte values, surrogate escapes, cursor precedence, depth and explicit
boundaries; the reused scanner's existing tests run as well.
