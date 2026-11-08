# Node 115 choice/weight MessagePack writer

This partial contribution advances #3912 by supplying an independently
authored Rust encoding of the selected normal-success `{choice, weight}`
record writer. The mapped struct writer previously delegated its qword to an
unsigned integer writer without an owned composition of the complete result.
The issue remains open and no component gate changes.

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032
bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Coordinates are linked ELF virtual addresses; FDE ends are exclusive. Base:
`0781ce04826eeefd89fe336cb8ea073be0c1de30`.

## Credited evidence and implemented contract

The merged [choice/weight struct packet](../action-wire-vote-choice-weight-struct-115/README.md)
(#4014) maps three clone bodies and their conditional field prefixes. The
[governance enum packet](../action-wire-gov-vote-codec-115/README.md) (#3379)
separately maps name codecs. The direct integer writer `0x25e9f10` was
previously examined in [direct integer width](../RE-012-snapshot-direct-integer-width-115/README.md)
and `RE-015-rmp-vecdeque-u64-115`. This packet binds its actual call at
`0x241cd2f`, verifies the full integer FDE and composes the selected bytes.
It does not re-claim the earlier enum or three-clone comparison as new.

For a stable mode byte 0, the complete result is an array marker `92`, the
choice string and the unsigned integer. Mode 1 yields map marker `82`, fixstr
`choice`, the choice string, fixstr `weight`, then the integer. Raw choice 0
writes `a3 yes`, 1 writes `a2 no`, and every other byte writes `a7 abstain`.
The integer uses positive fixint below 128; marker `cc` and one byte through
255; `cd` and big-endian two bytes through 65535; `ce` and four through
`u32::MAX`; otherwise `cf` and eight big-endian bytes.

The native record-header expression is `(((mode XOR 1) << 4) OR 0x82)`
truncated to one byte. The `choice` key is emitted for every nonzero mode,
while the `weight` key requires exactly mode 1. The source preserves these
raw-byte observations, including e.g. mode 2, but does not claim such mode
bytes are valid caller values or well-formed map/array framing. Choice bytes
above 1 take the observed fallback, not an invented validation policy.

`src/node115-vote-choice-weight` returns an owned fixed-capacity byte buffer and
exposes its active slice. It models no mutable native writer descriptor,
allocation/growth, intermediate failures or partial writes, native return tag,
aliased objects, unknown action envelope, request framing, signing, or
cryptographic operation. It assumes valid storage, stable mode/source fields
across writes and successful native allocation/helper calls. It does not
claim original ABI or full node behavior.

## Evidence and tests

`records.json` retains complete FDE-aligned windows for `0x241cb90..0x241cfa8`
and `0x25e9f10..0x25ea295`: 1,949 bytes and 505 decoded instructions. The
verifier authenticates the original ELF digest, FDE boundaries, exact retained
instruction rows and 52 selected facts, then rejects 21 corruption controls
with outer digest and window comparisons bypassed. These numbers describe two
selected bodies, not component coverage. No captured target was executed or
emulated.

Three Rust tests check exact field output, all 65,024 choice/mode fallback
combinations, and 7,680 separately generated Python `struct` packing fixtures
(256 mode bytes × 3 representative choices × 10 integer boundary values).
The reference is a synthetic model, not a native differential oracle. Tests
include 127/128, 255/256, 65535/65536, `u32::MAX`, `2^32`, and `u64::MAX`.
The Python fixture is deterministic and independently built from byte rules.

## Reproduce

```sh
python3 research/work-items/RE-005-node115-vote-choice-weight-source/verify.py
python3 research/work-items/RE-005-node115-vote-choice-weight-source/reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-vote-choice-weight/Cargo.toml
cargo +1.95.0 test --offline --release --locked --manifest-path src/node115-vote-choice-weight/Cargo.toml
cargo +1.95.0 clippy --offline --locked --all-targets --manifest-path src/node115-vote-choice-weight/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-vote-choice-weight/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-005-node115-vote-choice-weight-source/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

The verifier uses the existing audited Capstone 5.0.7 / Python 3.14.7
installation and project ELF helpers; no dependency is downloaded. Full
unfiltered `make test` is not run because discovery includes captured-code
emulation. Remaining work includes actual action-envelope binding, allocation
failure/partial-write behavior, parser/error paths, signing, and integration.

Implementation, packet, GitHub/browser and independent tests: OpenAI
`gpt-6.1-terra` / `codex-desktop`. OpenAI `gpt-6-astra` independently reviewed
the selected original instruction relations; no unlicensed source was copied.
