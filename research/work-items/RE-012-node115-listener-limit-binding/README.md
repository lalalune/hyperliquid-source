# Selected consensus listener: frame, LZ4 and typed-reader limit binding

Target: node115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Related #3911. Backlog HL115-029. This packet closes the three limit arguments and fresh typed-reader initialization for **one selected listener**, `0x2af8be0`. It does not claim that other callers use these values or that the full typed body has been reconstructed.

## Concrete result

| Stage | Bound quantity | Limit | Equality | Reset/scope |
|---|---|---:|---|---|
| Outer TCP frame | big-endian u32 payload length, excluding5-byte header |11,000,000|accepted|configured per selected frame-reader instance|
| Flag1 LZ4 | first4 payload bytes as little-endian declared decoded capacity |11,000,000|accepted|same saved frame limit, not remaining wire allowance|
| Typed reader | accumulated logical decode charges |11,000,000|accepted by selected primitive checks|fresh mode1, charge0 for each typed-wrapper invocation|

Equal numeric limits do not make these one budget. A small compressed body can fail its declared-output limit. Conversely an accepted11,000,000-byte raw frame still starts typed count0. The first20-byte identity plus u32 kind costs24 typed units even when its wire representation consumes21 bytes. There is no subtraction of the header, compressed length or decoded length from the typed budget in this initialization.

## Prior work and remaining novelty

#2076 establishes outer header admission/chunk planning, #2110 size-prefixed LZ4, and #3943 an offline frame stream. Main's `node115-frame-stream` takes one maximum for both stages as a chosen interface; it did not establish this particular native caller value. Open #5056 instead keeps outer and decoded bounds separate because caller equality was not known. #2628 already notes the selected listener's raw typed budget0xa7d8c0, but does not connect it to framing and decompression. #3339 concerns **another** typed wrapper `0x2700010 -> 0x2ce1590` with a bool/u32/u32 prefix; it must not be substituted for this listener's `0x27005e0 -> 0x2b6aea0`20-byte/u32 prefix.

The new contribution is the actual caller-to-three-stage argument/state join, with a usable source composition and fresh-budget witness. Existing frame, LZ4 and u32 implementations are dependencies, not copied or claimed anew. The independently authored20-byte prefix reader is a102-byte native closure; the payload body remains opaque.

## Original-ELF dataflow

1. Listener `0x2af9449..0x2af9477` initializes its frame-reader object at continuation+0x158. At `0x2af9465`, continuation+0x178 receives0xa7d8c0, hence frame-object+0x20 is11,000,000. At `0x2af8c3d..0x2af8c57`, the listener polls `0x2b788e0` with that object.
2. `0x2b7892b..0x2b7892f` copies input+0x20 into saved+0x28. The header helper `0x2b780d0` reads5 bytes; `0x2b78225..0x2b78233` byte-swaps the length DWORD and returns the fifth byte separately. `0x2b7903f..0x2b79043` accepts payload length<=saved limit. The five header bytes are not included in this comparison.
3. `0x2b791c6..0x2b791ca` marks compression only for flag==1. After complete payload collection, `0x2b79abd` loads the **same saved+0x28** as rcx; `0x2b79ace` calls slot `0x64e7790 -> 0x477f8c0`. This decoder requires at least4 bytes (`0x477f8d9`), reads the little-endian DWORD at `0x477f8ee`, and rejects declared output>rcx at `0x477f8f9..0x477f8fc` before allocation. Actual decoded output may be shorter than the declared capacity; the existing LZ4 result contracts remain authoritative. `0x477ff73..0x477ff8b` bounds returned length by the declared capacity.
4. After a successful frame, `0x2af8cf8` independently puts0xa7d8c0 into ecx and `0x2af8d03` puts zero into r8d, then `0x2af8d06` calls `0x27005e0` with the frame's bytes/length. This is not the frame's remaining allowance. In the selected r8=0 branch, `0x270069e..0x27006cc` initializes `[mode=1,limit=rcx,input,remaining,charged=0]` and calls `0x2b6aea0`. Reset occurs at each wrapper invocation, not at each nested reader call.
5. `0x2b6aec6 -> 0x2cd7d20` reads the20-byte identity; only its0x12 success tag reaches `0x2b6af16 -> 0x2cd79c0` for a u32 kind. The20-byte primitive charges20 before availability, commits no cursor on short input, and otherwise commits exactly20 and copies all20 bytes. The existing u32 reader charges4 irrespective of encoded width. Unknown kinds and all kind-specific bodies are downstream of the published prefix contract.

## Source composition and limits

`src/node115-listener-prefix` depends on the existing main-tree `node115-frame-stream` and `node115-u32-varint`, which in turn reuse the frame-plan/LZ4 crates. `ListenerPrefixReader::new()` selects11,000,000 for the existing frame reader. On a complete frame it invokes a fresh prefix reader with mode1 and limit11,000,000, retaining the typed cursor, charge and remaining body. Errors distinguish framing/decompression from the typed prefix, with prefix failure state retained.

This source returns a **prefix**, never a complete-message or authentication verdict. Identity origin, kind validation, body decoding/charges/refunds and full message acceptance remain external work. The standalone `decode_prefix` accepts already decoded bytes; it is not a wire-length gate. The20-byte charge overflow/limit arms cannot be reached from a fresh0 count with the selected11m limit, so the source specializes that state rather than exposing an unsupported arbitrary-reader API.

`feed`/`eof` inherit the existing offline adapter's one-frame terminal policy. It is explicitly a host API rule: connection reuse, cancellation, shutdown, buffered-byte disposal and post-error native continuation are not reconstructed. Each multi-frame test uses separate adapter instances and makes no claim about target reconnect policy. This keeps backlog HL115-028 distinct.

## Validation

```
python3 research/work-items/RE-012-node115-listener-limit-binding/verify.py
cargo +1.95.0 test --offline --manifest-path src/node115-listener-prefix/Cargo.toml
cargo +1.95.0 test --offline --release --manifest-path src/node115-listener-prefix/Cargo.toml
cargo +1.95.0 clippy --offline --all-targets --manifest-path src/node115-listener-prefix/Cargo.toml -- -D warnings
```

Use Capstone5.0.7. The verifier pins the original ELF digest, enclosing FDEs,9 selected windows,2,887 facts and30 corruption controls for limits, offsets, call edges, equality branches, fresh counter/mode and prefix fields. Controls bypass global/window hashes after original authentication so changed semantic facts must be rejected. Eight Rust test groups use hand-encoded big-endian headers and literal LZ4 blocks: exact flag behavior; split chunks and unconsumed suffix; outer L-1/L/L+1; declared decoded L-1/L/L+1 with a small compressed payload; a real accepted full-size raw frame; fresh typed count on separate invocations; all short identity lengths; and u32 encoded-width/cursor accounting. Original instructions are not executed or emulated; source tests are not native differential-equivalence measurements. Full transport and consensus component gates remain false.
