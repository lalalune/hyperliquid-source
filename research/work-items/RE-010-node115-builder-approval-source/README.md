# Node 115 builder approval writer source

Scoped progress toward [#3912](https://github.com/lalalune/hyperliquid-source/issues/3912).
The earlier `RE-010-builder-approval-115` packet established the native action
writer and its gates, but did not provide independent Rust source. This adds
actual owned keyed-state behavior for the complete selected logical approval
mutation at `0x3c1a510..0x3c1ae41`. Broader action acceptance remains unclaimed.

## Original target and evidence

Pinned `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Six full FDEs cover the writer, user entry helper `0x4717c50`, user equality
lookup `0x3ee6280`, builder deque lookup `0x4553fd0`, tree removal `0x3901f10`
and tree insertion `0x3710950`. The packet contains 4,035 bytes / 883
instructions, 674 semantic facts and 29 corruption controls. The verifier
checks original ELF identity, FDEs, instruction operands, actual child bindings
and imported 20-byte comparison. Controls bypass outer digest/window checks.
This is static evidence, not native runtime equivalence.

## Recovered behavior

The writer resolves a full 20-byte user key and calls `0x4717c50` **before**
testing fee or count. Its vacant-user initializer sets the approval-map header
and length to zero. The owned projection therefore inserts a missing user with
an empty approval map even for a zero-fee operation.

- Fee zero removes the full 20-byte builder key if present and returns `0x1a2`.
  Missing builder is also successful. This path bypasses the count gate.
- Fee nonzero first reads the current approval count. A count greater than ten
  returns `0x13c` without an approval change, before builder lookup. Consequently
  an update to an existing builder is rejected at count eleven too.
- At count ten or below, the full builder key is inserted or its raw u64 fee is
  replaced, returning `0x1a2`. A new key at count ten becomes the eleventh entry.

The `32`/`64` thresholds elsewhere in this owner select physical tree/deque
conversions; they do not add logical business limits. The owned `BTreeMap`
implements key lookup, insert, replace and remove directly. The source neither
mocks a child result nor changes the observed count boundary. No fee ceiling,
unit conversion, string parsing or outer authorization is inferred here.

## Validation

`tests/reference.py` maintains independent list-based user approval state,
then emits expected full maps after every operation. It covers 142 scenarios
(each initial count 0 through 70 twice), totaling 5,680 actions: 4,252 accepted
and 1,428 count rejections. The fixture SHA-256 is
`12fe62eb2f7f7a95eb7b25979e5d335f1233568ac3a0ac90675964aea5de788f`.
Rust compares all user keys, builder keys and raw fees after each action.
Explicit cases check the tenth/eleventh boundary, rejection of existing-key
replacement above ten, deletion and subsequent replacement, missing-user zero
creation, and full-key distinctions at both ends of the address.

```sh
python3 src/node115-builder-approval/tests/reference.py
cargo test --offline --locked --manifest-path src/node115-builder-approval/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-builder-approval/Cargo.toml
cargo fmt --check --manifest-path src/node115-builder-approval/Cargo.toml
cargo clippy --offline --locked --all-targets --manifest-path src/node115-builder-approval/Cargo.toml -- -D warnings
python3 research/work-items/RE-010-node115-builder-approval-source/verify.py
make doctor verify catalogue-check reproduce
```

All three tests pass in debug/release; fmt and clippy pass. The verifier rejects
all 29 controls. Only inspected safe Python repository tests are used; the
unfiltered suite contains captured-instruction emulation. Neither captured
instructions nor the target executable were executed or emulated.

## Overlap and limits

Current main source inspection, all-state builder-approval PR metadata searches
and all 55 open PR titles/changed paths found no matching owned implementation.
The earlier node94 [#328](https://github.com/lalalune/hyperliquid-source/pull/328)
is a separate release and is not used as evidence. Existing node115 static work
is credited above. This audit does not individually inspect every closed patch.

Premises: valid logical keyed maps and successful allocation. This is the
approval-map projection of each user; unrelated user fields and their default
initialization are excluded. Physical native hash/map ABI, tree balancing,
deque conversion, allocation failure and unwinding are excluded. The outer
request decoder, signature/authorization checks, fee units and downstream
exchange effects are not implemented. No component acceptance gate changes.
