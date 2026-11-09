# Node 115 complete disabled-state record encoding

This scoped contribution advances issue #3920 with an independently authored
encoding of the selected successful five-field per-DEX record. The issue remains
open and no component completion gate changes. The new outcome is the complete
owned byte composition, including both timestamps, rather than another enum
inventory or a serializer with substituted field helpers.

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Coordinates are linked ELF virtual addresses; FDE ends are exclusive. Base:
`0781ce04826eeefd89fe336cb8ea073be0c1de30`.

## Prior work and new boundary

The merged [disabled-state codec packet](../RE-007-hip3-disabled-state-codec-115/README.md)
(#3390) maps the record's field order, three native writer clones and enum table,
but leaves the time, unsigned value, final byte and string helpers abstract.
The enclosing Main/Hip3 variant (#3361) and JSON path (#3364) are separate.
This contribution credits those observations and implements one selected
MessagePack writer at `0x2bc06a0`; it does not claim new clone discovery.
The prior [subrecord helper packet](../dex-registry-hip3-subrecord-helpers-115/README.md)
(#3367) already identifies the `Time` newtype, the `T` separator, and a
boolean marker in sibling helpers; this contribution binds the selected record
to its own helper path and composes the complete owned output.

The existing `src/node115-date-time-display` (#2808), with evidence in
`RE-012-date-time-display-115`, already implements the date and time formatting
leaves. This crate depends on that source directly. It neither copies nor
reimplements the calendar or fractional-second algorithm. Its `Date` and `Time`
constructors define the accepted timestamp domain, including conventional leap
seconds. The native record's intervening `Time` newtype, `T` separator, string
framing and field composition are established here.

At the stated base, the reused dependency's `Cargo.toml` SHA-256 is
`2d3472d11bba45c09599f61cef467f83e80c59bde006e91a3ce9c6023090bcd4` and
`src/lib.rs` SHA-256 is
`3b373cae2a0e3ded77b7d550ca669bd66028274a4f380f64ddd6f133242579a7`.
Its evidence packet README SHA-256 is
`073ad76e6bf9c0e5b0856e9710ccff09c376f3729b22e03c69b7fe9a33c6987e`.

## Observed record and helpers

| Native input | Wire field, in output order | Selected relation |
| --- | --- | --- |
| `+0x08`, 12 bytes | `last_settlement_time` | `0x2bc0735` passes the first time to `0x226f130` |
| `+0x14`, 12 bytes | `deploy_time` | `0x2bc0783` passes the second time to the same helper |
| `+0x00`, qword | `n_reserve_deployments_used` | `0x2bc07d9` calls unsigned writer `0x25e9c70` |
| `+0x20`, byte tag | `disabled_state` | table `0x60922c` maps 0/1/2/3 to `Na`/`UserDisabled`/`ValidatorDisabled`/`m` |
| `+0x21`, boolean byte | `m` | `0x2bc08a3` calls `0x226a240`; this emits `c2`/`c3`, not an integer |

For supported mode 0 the record begins with array marker `95` and contains five
values. Mode 1 begins with map marker `85` and writes each key before its value.
The native disabled-state key checks mode != 0, whereas the other four keys
check mode == 1. The public `Mode` enum deliberately exposes only these two
supported values, where the guards agree; malformed writer modes are outside
the contract. `DisabledState::M` retains an observed label without assigning it
an unproved business meaning. The final `m` field is a separate boolean.

`0x226f130` receives the literal `Time` with length 4. Its special `_ExtStruct`
branch requires length 10, so this caller reaches `0x227e960`. That function
passes the first four bytes to date display through relocation
`0x64e1158 -> 0x1628bc0`, appends ASCII `T` through the actual String `write_char`
vtable entry `0x642c218 -> 0x21f3630`, then passes the remaining eight bytes to
time display through `0x64e1160 -> 0x162a760`. The resulting string is handed to
`0x25e8750`. There is no space, timezone suffix, or binary extension wrapper.

The date/time dependency supports signed years and fractional precision 0, 3,
6 or 9. Their joined timestamp is at most 32 ASCII bytes. The actual string
writer uses fixstr below 32 and `d9` followed by a one-byte length at 32. The
same helper writes every fixed field key and enum label, which all fit fixstr.
The packet also binds the copy import, payload length update and character
append; the `T` byte is not inferred only from a nearby literal.

The unsigned writer uses fixint for 0..127, `cc` for 128..255, `cd` for
256..65535, `ce` through `u32::MAX`, and `cf` otherwise. The three wider
branches call `0x25ea4b0`, `0x25ea780`, and `0x25ea910`; their actual marker,
byte reversal and length increments are retained. Boolean helper `0x226a240`
ORs the valid input with `c2`, and `0x25eab50` preserves these marker bytes.

The new `no_std` crate returns an owned encoding, using a 192-byte buffer. The
largest supported map is 174 bytes: 78 bytes for map framing and all keys,
68 for two 32-byte str8 timestamps, 9 for the counter, 18 for
`ValidatorDisabled`, and 1 for the boolean. Three tests cover exact framing,
that maximum, and 3,520 independent Python fixtures: 2 modes × 4 states × 2
booleans × 11 unsigned boundaries × 20 timestamp pairs. The Python reference
uses `datetime` for calendar conversion and a recursive object-to-MessagePack
packer, independently of the Rust implementation. It is a synthetic reference,
not a native execution oracle.

## Evidence, validation and limits

`records.json` retains 13 complete FDE-aligned windows: 6,164 bytes and 1,587
decoded instructions. The verifier authenticates the whole target digest,
function boundaries, instruction rows, 417 selected instruction/data/edge
facts, and 32 corruption controls. Controls alter field sources/order guards,
timestamp routing/separator, enum mapping, bool type, integer boundaries and
byte order, string threshold, marker choice, and formatter relocations. Their
checks run with the outer digest/window comparisons bypassed. These counts
describe the selected contract and are not component coverage.

Supported inputs use the existing checked date/time types, four enum variants,
boolean `m`, and a stable mode and record. The native success path assumes valid
non-aliasing descriptors and successful allocations/copies. Owned output does
not reproduce native buffer growth, out-of-memory behavior, partially written
error results, or the original ABI. It does not implement a parser, enclosing
Main/Hip3 variant, JSON, request dispatch, authorization, or DEX state mutation.
No captured target was executed or emulated, and no live service was contacted
to validate behavior.

```sh
python3 research/work-items/RE-007-node115-hip3-record-source/verify.py
python3 research/work-items/RE-007-node115-hip3-record-source/reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-hip3-disabled-record/Cargo.toml
cargo +1.95.0 test --offline --release --locked --manifest-path src/node115-hip3-disabled-record/Cargo.toml
cargo +1.95.0 clippy --offline --locked --all-targets --manifest-path src/node115-hip3-disabled-record/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-hip3-disabled-record/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-007-node115-hip3-record-source/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

The static verifier uses the existing Capstone 5.0.7/Python 3.14.7 installation;
Rust uses the already installed 1.95.0 toolchain, with no downloaded dependency.
Full unfiltered `make test` is excluded because discovery includes captured
instruction emulation. The retained validation report lists the focused safe
repository tests and actual outcomes.

Implementation, original-binary research and reference: OpenAI `gpt-6-astra` /
`codex-desktop`. GitHub/browser reads, independent review and publication:
OpenAI `gpt-6.1-terra` / `codex-desktop`. Existing project source retains its
authorship and MIT license; no unlicensed inferred source was copied.
