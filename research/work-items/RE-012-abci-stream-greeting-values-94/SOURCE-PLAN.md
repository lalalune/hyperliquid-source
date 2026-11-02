# Proposed source integration, requiring a separate gate

The pre-code packet contains no new Rust source, client, build harness or
production dependency changes. After independent review and a separate source
gate, propose one actual standalone MIT crate at
`src/node94-abci-greeting-values/{Cargo.toml,Cargo.lock,README.md,src/lib.rs,tests/vectors.rs}`.
This is the complete supplied-reader greeting operation, not an isolated helper
or test-only feature. Keep framing, sockets, startup state and peer authentication
outside its API. No existing production API needs to change.

Use the already merged MIT `hl-bincode-varint` path dependency at
`../bincode-varint`, with no external packages, build scripts or features.
`source-dependencies.json` records the currently read provider inputs; the
coordinator must compare them against a clean current-main source checkout
before authoring/build admission. The baseline public types are `PayloadOrder`,
`ReaderError`, `DecodeError`, `DecodedU64`; the actual APIs are `read_u32`,
`read_u64`, and `decode_u64_slice_fast`. Credit the merged varint, slow-width and
Reader Rust packets. Open PR1365's wrapper state work is prior related evidence,
not a runtime source dependency or permission to copy its pending source.

Privately compose those baseline scalar APIs with this packet's proved charge,
fast/slow dispatch and error mapping. For a u32 fast input, precheck unsupported
markers before using the baseline Reader for a supported value, so invalid
markers consume zero. For a u64 fast input, use the existing fast decoder and
map the known raw marker categories to expected code2. Slow Reader errors keep
their native cursor changes. The usize leaf has the same admitted value/cursor
relation as u64 but invalid expected code5; represent its logical value as u64,
not an unchecked host usize cast. These compositions must be source-proved and
tested; mere shared names are insufficient. Disabled charging and canonical
limit tags must remain explicit.

Expose a safe Reader state carrying a borrowed immutable input, cursor, optional
u64 limit and u64 charged count, with checked cursor construction. Parsing returns
either the complete logical greeting or one of the five active native errors;
the Reader retains its post-read state on both outcomes. Expose a separate
selected-caller adapter that starts a fresh enabled Reader and returns the
logical value plus optional consumed count. Preserve the distinction that its
native caller does not return the internal charged/cursor fields on error.

Owned logical values should use ordinary safe containers: V bytes, H `[u8;32]`,
key `[u8;20]`, signature `([u64;8],u8)`, three fixed-size records and a standard
ordered map. A map's duplicate replacement and byte ordering must match the
proved relation; native B-tree shape, allocator sizes and pointer identity are
not API claims. Do not reserve a wire-count-sized allocation before decoding:
native maps start empty and a huge count can fail on the first row. Keep failure
and ownership order equivalent in values/state under successful host allocation.
Any host allocation/size refusal is a separately named safe policy, with no
claim about native allocation failure atomicity or destructor side effects.

Before any compilation, freeze the full actual crate/provider graph, tests,
input-only client and qualification harness. Audit real Cargo manifests/lock,
ancestors and both lexical/canonical temporary roots, symlinks, build hooks,
configuration/environment, executable identities and the pinned toolchain
payload. Use actual dependency paths; no fake workspace or expected-output
generator linked into source. The parent gate must authorize the frozen build.

Later qualification should run the actual library/tests and input-only client
in debug and release, offline/locked, with complete frozen outputs, malformed
transport controls, source mutants and retained first/repeat artifacts. Useful
compiled mutants include wrong strict threshold; always Reader; u64 expected3
on fast rejection; rollback; limit check before charge store; saturating charge;
omitted group reservation; map refund omitted or85 instead of96; multiply wrap;
first duplicate wins; signed key comparison; swapped map/scalar/record order;
zeroing recovery byte; invented EOF kind0 for bulk vector; trailing-byte refusal;
and error consumed count invention. Each must compile and produce a full result
stream before a semantic mismatch is counted. Mutants are planned, not yet run.
