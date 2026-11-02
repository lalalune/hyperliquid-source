# RE-012: initial greeting reply routing

Target: Linux x86-64 node94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `7c369234cef4e5e61d8cf260f6ba7ce949537408` (PR #1889).
Question: after a greeting reply decodes successfully, which replies does its
caller reject, which preserve the stream, and which require further checks?

The independent Rust component now supplies `Request::route_reply` and
`greeting::exchange_routed`. The latter composes the existing framed exchange
and complete decoder with this initial routing, preserving all decoded fields
and cursor/charge metadata. It exposes four named rejection reasons. A data
reply returning `ValidateState` still requires the missing state validation.
Neither route is peer authentication or complete peer acceptance.

## Binary findings

`CONTRACT.md` was written before the implementation and records the table.
The seven retained FDEs span 37,290 context bytes; 381 selected instructions,
two complete relative dispatch tables, one initial-state table entry, five
relocation records and five error strings
are bound in `anchors.json`. These are analyzed bytes, not matched Rust bytes.
GNU and LLVM listings are retained for each full FDE, with exact commands and
stdout hashes in `native-exports.json`.

The caller `0x22615b0` invokes the established greeting future `0x2037ac0` at
`0x22626ec`. Its successful reply dispatch subtracts two with unsigned
saturation from the native tag and uses table `0x3d5ce4`. Native tags 0..2
(the three nested data variants) therefore share a branch; native tags 3..7
map to outer wire variants 1..5. This does not reinterpret the independent
Rust enum as a native memory representation.

The controlling flag is the first transmitted request byte, not the second
byte or the header timer. In the caller AL is stored at state `+0x1f1` and
`+0x4a`. The first store lies in the object starting at state `+0x68`; its
offset is `0x189`. Copies to state `+0x530` and a stack temporary preserve it.
The wrapper `0x2002760` copies that object into the greeting future at `+0x78`:
`0x189 + 0x78 = 0x201`. This is the original first byte loaded at `0x2037b70`
in the preceding greeting-exchange packet. The second store supplies R13B
at `0x2262d1b`; it is also preserved across async resume in state `+0x830`.

For data variants, R13D is copied to R14D at `0x2262f75`, through stack `+0x20`
to DL at `0x22630b7`, and tested with `test dl,1` at `0x22630e6`. Nested hash
2 takes cleanup before that test; hash 0/1 continue only when bit zero is set.
The empty-success outer variant 3 instead uses `test r13b,r13b` at
`0x2263fe2`, preserving the stream only for an exactly zero byte. The API
preserves this distinction without claiming that every raw byte can originate
from the original nominal Rust type.

The native rejection constants are bound to the formatter `0x4de31e0`, its
relative table `0x713e00`, and these exact messages:

| Wire reply | Native sentinel | Message |
| --- | --- | --- |
| Outer 1, wrong first-byte/data combination, or nested hash 2 | `2^63 + 0x33` | Peer inconsistent greeting |
| Outer 2 | `2^63 + 0x32` | Peer no quorum l1 hash |
| Outer 4 | `2^63 + 0x2f` | Peer full |
| Outer 5 | `2^63 + 0x31` | Rate limited by peer |

The intervening formatter entry `2^63 + 0x30` means a connection timeout;
it is retained as context and is not assigned to a successful reply selector.
The caller's reject paths invoke `0x2253890`, which closes a nonnegative
stored descriptor via the `close` import. Outer 3 with a zero first byte
bypasses that cleanup and restores the stream result. The component still
borrows generic caller-owned I/O, so it explicitly requires stream disposal on
errors; it does not pretend that a generic borrow can close a descriptor.

## Evidence, validation and limits

`verify.py` authenticates the complete artifact before checking the retained
bodies, instructions, tables, strings and relocation tuples. Its fixed-layout
mutation seam is explicitly unauthenticated. The focused Python tests corrupt
each selected instruction, the complete-body tails, tables, strings, imports
and relocations; they also require agreement on instruction starts from both
native listings. This checks evidence integrity, not a proof of the inferred
control-flow semantics.

The Rust tests cover all 256 first-byte values and all eight logical reply
variants against the prior contract table, different payload fields, the
irrelevance of the second byte/header flag to routing, metadata preservation,
no read into the next frame, and transport/decode/rejection ordering. Compiled
wrong-source controls and actual build/test receipts are retained separately.
Only the independent Rust and offline tooling execute; captured code does not.

Reproduce with:

```sh
python3 research/work-items/RE-012-greeting-policy-94/verify.py
python3 -m unittest discover -s tests -p test_greeting_policy_evidence.py -v
cargo test --offline --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features
cargo test --offline --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features --release
cargo build --offline --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features --release --target x86_64-unknown-linux-gnu
make verify test catalogue-check reproduce
```

Direct REA section-header evidence is retained in `rea-sections.json`. The
connected target-free GNU interface accepts a symbol but no address bounds;
this stripped, unsymbolized corridor needs address-scoped native calls. The
installed GNU/LLVM tools provide those calls without starting another Ghidra
analysis. No REA setup, registration, or captured execution was performed.

This work builds on the prior frame, deadline, exchange and complete reply
packets. It changes no milestone gates, registered byte windows, dependencies
or imported evidence. The data-state validation path, its called helpers,
retry/backoff policy, ownership of an integrated connection, network discovery,
synchronization, and the source-built node/Docker image remain unfinished.
