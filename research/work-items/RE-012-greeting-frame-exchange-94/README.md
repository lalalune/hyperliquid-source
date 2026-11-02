# RE-012: initial greeting request and reply-frame exchange

- Component: `transport`, source base `b4c44abd0a7a2091df5c49e2491f3983d89f5bef`.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Question: after a connection exists, which bytes and deadlines does the
  initial greeting use, and which limit/header flag reaches its reply reader?
- Result: independent Rust for the request-through-reply-frame interval.
  The semantic reply decoder is explicitly outside this API's completion point.
- Changed implementation: `src/node94-tcp-frame/src/{greeting.rs,lib.rs}` and
  its tests/README. No new dependency, root workspace or lockfile is introduced.

## Contribution and scope

The codec, asynchronous I/O and deadlines previously existed as separate
operations. `greeting::exchange_frame` now joins them with the observed initial
request, timeout selection and reply limits. It sends the full request before
reading the reply, returns exactly one decoded frame, preserves its complete
payload, and distinguishes send from receive failures. The returned bytes
must still be validated before accepting a peer. This is a usable transport
boundary for the later node; it is not a replacement for the missing decoder.

The request serializer is credited to pending PR #1706 at
`4b859510984d14a18c270ab338797033db3477c0`, whose manual proof was inspected.
The reply limit and later result envelope are credited to PR #1723 at
`72b7a41d30b40ef105c9fec5a713f6726162e5cb`. Their claims were treated as leads,
not approvals or substitute validation. This packet independently checks the
selected native bytes and adds source implementation plus the explicit binding
of original byte `+0x203` to the reader's header-timing flag. Neither pending
packet is imported or executed as a runtime dependency. Their semantic result
and ownership claims are not claimed by this API.

The prior frame/deadline packets retain their scope and credit. No can1357
source was copied. Request byte names `first` and `second` deliberately do not
assert protocol roles or reachable original Rust representations.

## Observations and source interpretation

All addresses are linked ELF virtual addresses. `anchors.json` retains five
complete FDE extents (7,517 bytes of context), their raw hashes and 63 selected
instructions. GNU and LLVM full listings are retained separately. Those byte
counts are context, not reconstructed or matched machine-code credit.

| Extent | Bytes | Role in this interval |
| --- | ---: | --- |
| `0x2037ac0..0x2039053` | 5,523 | Fresh post-connect caller; request handoff and reply reader arguments |
| `0x28c0b90..0x28c10c9` | 1,337 | Serialization wrapper and successful vector handoff |
| `0x28c14f0..0x28c162d` | 317 | Size/allocation/write composition |
| `0x25599e0..0x2559a3c` | 92 | Three-byte size, starting from zero |
| `0x2559a40..0x2559b38` | 248 | Preserve two source bytes and append zero |

The caller loads its original word at `+0x201` at `0x2037b70`, copying it to
`+0x1f0`. Original byte `+0x203` is copied separately to `+0x1f8` at
`0x2037bb2..0x2037bb9`. These are three independent raw source bytes, not three
transmitted fields.

At `0x203808f`, the two-byte source address reaches serializer wrapper
`0x28c0b90`. The zero EDX argument chooses its normal non-TLS-bracketed route;
`0x28c0d3c` calls `0x28c14f0`. That entry initializes size state to zero,
calls `0x25599e0` to obtain three, allocates that capacity and initializes
length zero before calling `0x2559a40`. Its stores at `0x2559a5e`,
`0x2559a76` and `0x2559a85` produce `[first, second, 0]`. The comparison
against source byte 1 in the size helper has its flags overwritten before the
next branch; it does not normalize that byte. The wrapper's successful vector
reaches the writer's pointer/length argument at `0x203810e`.

The caller sets writer flag zero at `0x20380eb`, despite carrying f64 60 in its
next word. The existing writer analysis therefore selects the 20-second
**default**, not the carried override. Three payload bytes always take its raw
branch, independent of the stream field. Existing frame construction gives
`00 00 00 03 00 first second 00`. The Rust call supplies zero for the irrelevant
compression-policy stream-field argument; it assigns no port or peer role.
The caller does not reach its receive setup until the writer has completed
without error (`0x2038133`, `0x203816f..0x2038172`). Pending and failed sends
must not start a reply read.

At `0x20382b2`, the first original byte selects 1,000 when zero or
3,000,000,000 otherwise via `0x20382bb..0x20382c5`. The separately retained
original `+0x203` byte is loaded at `0x20382c9`, then stored at parent `+0x210`
at `0x2038346`. The reader argument starts at parent `+0x208`; that is its
`+8` header-timing flag, already established by the deadline packet. The limit
is stored at reader `+0x20` (`0x203835b`). `0x203837a` invokes `0x2049950`.
Thus neither transmitted byte controls header timing in this interval.

After the frame returns, `0x20384d8` invokes the semantic decoder wrapper
`0x28bdc00`. This proves the boundary of the new API: raw frame return occurs
before that missing semantic validation. Selected simple replies in #1723 do
not close the complex variant. Focused inspection here found the selected
`0x25618f0` decoder's selector 0 reaches byte-vector helper `0x2891c30`, a
u64, then `0x255eba0`; its nested variants reach additional decoders including
`0x1f646e0` and `0x21cca20`. Those paths remain research under ignored work/;
this packet neither models them as opaque success nor invents replacement
wire types. Completing that decoder is the next integration task.

## Verification and implementation limits

`verify.py` reauthenticates the whole target and checks the five extents and
63 instructions. It also reruns the existing writer analysis to bind this
exact call to the 20-second choice. Its separate structural inspection seam
never grants authentic origin to a changed image. Four focused Python tests
change every selected instruction below the digest check, verify native
instruction starts independently, and reject truncated input. These are
sensitive-binding checks, not a formal proof of every instruction in the FDEs.

`rea-sections.json` preserves the direct REA 6.8.0 GNU section-header evidence
`ev_b001c514385a090ff68d986106d0cb1e551352b763d45ac0c136e94d3e57f450`:
same target hash, exit 0, complete output, no truncation. Its installed objdump
API has no address-range selector; local GNU/LLVM commands supply the bounded
listings in `native-exports.json`. No tool registration or architecture changes
were required.

Twelve Rust tests cover all 65,536 request-byte pairs with both timing flags,
fragmented request/reply I/O, full payload and suffix preservation, LZ4,
inclusive 1,000-byte admission, over-limit headers before allocation, forged
decoded length, error stages, no read after send failure, 20-second send timing,
independent header timing, timed payload and cancellation after transmission.
The larger 3,000,000,000-byte limit is checked as a value and by rejection above
it, without allocating a three-gigabyte fixture. Seven compiled wrong source
variants and their test output are retained in `rust-mutations.json`.

```sh
make doctor verify
python3 research/work-items/RE-012-greeting-frame-exchange-94/verify.py
python3 -m unittest discover -s tests -p test_greeting_frame_exchange_evidence.py -v
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features --release
cargo clippy --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-targets --all-features -- -D warnings
cargo fmt --manifest-path src/node94-tcp-frame/Cargo.toml -- --check
cargo build --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features --release --target x86_64-unknown-linux-gnu
make verify test catalogue-check reproduce
```

See `VALIDATION.md` and the receipts for actual outcomes. This implementation
uses an existing caller-owned stream and time driver, with no flush, close,
socket creation, endpoint choice, connection retry, peer acceptance or signer.
Timeout/cancellation may leave partial bytes, requiring connection disposal
unless its boundary is independently restored. The target's potentially large
reply limit is preserved; resource policy still needs to be integrated by a
real node. Original allocator/error ABI, diagnostic/TLS behavior, lifetime
cleanup and all caller paths are not reconstructed here.

No component gate, byte-window count or node-completion percentage changes.
There is still no integrated node executable, source-built Docker image,
network-compatibility run or synchronization acceptance result.
