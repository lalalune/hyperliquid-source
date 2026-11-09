# Node 115 referral-code registration and modification source

Scoped progress for [#3912](https://github.com/lalalune/hyperliquid-source/issues/3912).
The prior [#2198](https://github.com/lalalune/hyperliquid-source/pull/2198)
mapped the native boundaries; this contribution adds independent owned Rust
for the core's registration and modification branches, plus the normal
registration wrapper's status/tag projection. Broad acceptance gates remain
unchanged.

## Original evidence

Pinned `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Ten complete FDEs retain 9,443 bytes / 2,135 instructions, 1,856 checked
instruction/dataflow facts and 40 corruption controls:

| Entry | Role |
| --- | --- |
| `0x3c193d0` | Registration/modification logical core |
| `0x285c730` | Normal registration wrapper |
| `0x4716f00` | Exact 20-byte volume-user lookup |
| `0x37c6220` | Actual volume-row iteration |
| `0x3ccb770` | Referrer entry lookup |
| `0x3cc9c90` | Code entry lookup |
| `0x39023e0` | Tree old-code removal |
| `0x4556ea0` | Deque old-code lookup |
| `0x370b790` | Tree referrer insertion |
| `0x3709200` | Tree code insertion |

The wrapper's relocated call slot `0x64e6a38` binds to `0x3c193d0`.
Imported `memcmp` is bound for complete string and 20-byte key comparisons.
The full core also retains inline/delegated deque mutation paths. The Rust
uses owned keyed maps rather than reproducing native physical containers.

The verifier authenticates the original ELF digest, FDEs, retained instructions
and semantic facts. Each corruption must fail the fact checks with outer
digest/window checks bypassed. This validates static evidence, not native
runtime equivalence.

## Recovered behavior

`Mode::Register` corresponds to the zero mode byte. It resolves the actual
user's reward/volume rows and saturating-sums each row's first raw `u64` word.
Missing user or a sum below 1,000,000 returns `0xa9`, before the core's length
check. A code longer than 100 UTF-8 bytes returns `0xa4`. An existing referrer
record returns `0xa8`. An occupied code returns `0xa7`, even if its owner is
this user but the user's referrer record is absent. Otherwise the core inserts
a referrer record with the owned code, empty history, zero remaining quota,
zero bucket and supplied configured quota, then inserts code-to-user mapping.

`Mode::Modify` corresponds to a nonzero mode byte and bypasses the volume gate.
Length is checked first. An absent referrer uses the same vacant-code/new-record
path. For an existing referrer, a requested code owned by another 20-byte user
returns `0xa7`. A vacant code or one already owned by this user is accepted:
remove the old record's code from the index, insert the requested code-to-user
mapping, replace the owned code and configured quota, and reset the bucket to
zero. Existing history and remaining quota are preserved. No global index/
record consistency is assumed: old-code removal follows the recorded old key.

The mode-dependent gates are at `0x3c193f2..0x3c196fc`; the volume source,
saturating fold and threshold are at `0x3c195d0..0x3c19621`. Existing-record
code ownership is checked at `0x3c19936..0x3c19976`. New-record defaults are
at `0x3c19991..0x3c199d4`; final modification writes are at
`0x3c1a104..0x3c1a114`. The remaining field at `+0x38` is preserved while
bucket `+0x40` resets and configured quota `+0x48` changes. Success is `0x1a2`.

Codes are exact case-sensitive UTF-8 byte strings. Empty strings, embedded NUL
and non-ASCII strings are not rejected by this selected core. The byte limit
is not a Unicode-character count. `Mode` does not provide authorization.

The normal registration wrapper first rejects byte length >=101 with error
`0x158`, even if the user lacks qualifying volume. It invokes the core in
registration mode with configured quota zero. Core success becomes tag `0x0e`;
wrapper/core errors become tag `0x0f`. `RegistrationReply` retains only this
status/tag projection, not the native error payload or result ABI.

## Validation

The independent Python reference uses dictionaries and arbitrary-width sums,
clamping volume once to `u64::MAX`, rather than Rust's incremental saturating
fold. It generates 200 deterministic initial states and 4,000 sequential
actions. Rust compares status, wrapper tag, entire referrer/code maps and
unchanged volume maps after every action. The fixture includes missing rows,
exact/overflowing volume sums, collisions, aliases, case changes, empty/NUL
strings, 100/101-byte ASCII and 100/102-byte Unicode values, and preserved
history/remaining quota. There are 1,004 successful actions: 844 modifications,
87 direct registrations and 73 wrapper registrations. Fixture SHA-256:
`7dc17c57bc08f1b54a6d0b50aacd44d25e15905d8d991b9b00d730ad1367db2a`.

Four tests pass in debug and release. Explicit cases cover core/wrapper error
precedence, same-owner alias changes, collision immutability, zero wrapper
quota and the absent-record/occupied-code distinction. Formatting and clippy
pass. All 40 semantic corruptions are rejected, including changes to mode,
volume source/overflow/threshold, length/status boundaries, owner comparison,
record defaults, old-code removal, preserved remaining quota and wrapper tags.

```sh
python3 src/node115-referral-code/tests/reference.py
cargo test --offline --locked --manifest-path src/node115-referral-code/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-referral-code/Cargo.toml
cargo fmt --check --manifest-path src/node115-referral-code/Cargo.toml
cargo clippy --offline --locked --all-targets --manifest-path src/node115-referral-code/Cargo.toml -- -D warnings
python3 research/work-items/RE-010-node115-referral-code-source/verify.py
make doctor verify catalogue-check reproduce
```

Repository validation uses inspected safe Python tests, excluding the unfiltered
suite's captured-instruction emulation. No captured code was executed or
emulated and no live exchange operations were performed.

## Overlap and limits

Current-source inspection, all-state referral-code/ModifyReferrer PR metadata
searches and all open PR titles/paths found no matching owned source. The
node115 static work #2198 is credited above; [#345](https://github.com/lalalune/hyperliquid-source/pull/345)
concerns node94, a separate release. [#4390](https://github.com/lalalune/hyperliquid-source/pull/4390)
consumes code mappings to assign users and debit quota; this contribution
registers/modifies those mappings and referrer records. These checks do not
individually inspect every closed historical patch.

Premises: valid logical keyed maps, valid UTF-8 strings, successful allocation
and normally returning diagnostics. Physical hybrid-map layouts, hash probing,
collection conversion, allocation failure/unwinding and diagnostic effects
are excluded. History timestamps are preserved opaque three-word payloads.
Outer action decoding/normalization, governance envelope and authorization,
native error payload/result layout, live state, user referral assignment and
quota consumption remain outside this contribution's scope.
