# First nonzero portfolio pass: request sequencing and local replacement

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `a8616af9432b8d8517b2af677880e117b7c28ef3`. Bounded static advance of HL115-048. No captured target execution or emulation.

The first R9B-nonzero pass of `0x2c64870` transforms mutable 16-byte key/value rows through `0x2c619b0`. This packet establishes the actual two-request sequence and how each returned record replaces a 56-byte local context before the next request. It makes the previously opaque transformation usable as a concrete integration boundary without inventing the request helper's business rules.

## Prior work and new scope

[#2154](https://github.com/lalalune/hyperliquid-source/pull/2154) establishes the portfolio seed/residual behavior for the R9B-zero route. Existing `RE-006-node115-argument-producers` already locates both `0x2c619b0` calls to `0x2c62820` and their `0xf8`-byte result copies. `RE-006-node115-element-argument` establishes consumer argument provenance. These boundaries and copy sizes are reused. The new result joins the caller's nonzero mode and mutable row to request tags/quantities, the selected returned-record state replacement, and the write of the remaining quantity back into the same row.

This is the first nonzero pass only. The later request-3/request-0 loop, general simulation semantics, business names for the raw tags, original-state isolation, secondary-map mutation and complete HL115-048 acceptance remain open.

## Actual row and request lineage

The caller saves R9D and later tests its low byte at `0x2c64e8f`; zero bypasses this pass. The local map descriptor at stack `+0x80` supplies a mutable iterator, using a 16-byte stride in its flat representation. `0x262e7f0` yields key/value addresses. At `0x2c64fcd`, `0x2c619b0` receives the original owner and 20-byte identity, the row's key and current quantity, the saved ECX mode, a first local context at stack `+0x30`, and a second local collection at stack `+0x118`. At `0x2c64fd2` its returned quantity is written to that same yielded value address before advancing the iterator.

The first request to `0x2c62820` has this observed layout:

| Request offset | Actual value |
| --- | --- |
| `+0x00` | raw qword tag 2 |
| `+0x08` | current row quantity |
| `+0x10`, `+0x18` | first local context and second local collection pointers |
| `+0x20` | row key |
| `+0x28..+0x3b` | original 20-byte identity |
| `+0x3c` | saved mode byte |

If the returned dword tag is 3, the helper returns the unchanged quantity without invoking the record consumer. Otherwise it copies the returned `0xf8`-byte record and invokes the actual consumer `0x3f10ac0` through relocation `0x64e7e60`, using those same two local pointers. The returned consumed quantity is compared unsigned with the available quantity. Underflow goes through the existing diagnostic helper and returns zero if that helper returns normally; exact exhaustion also returns zero. A positive remainder causes a second request with raw tag 1 and **that remainder**, retaining the key, identity, owner, mode and both mutable contexts. A second tag-3 result preserves the current remainder; otherwise the same record consumer runs and its returned quantity is subtracted with the same zero-on-underflow continuation.

The order matters: the second request sees the first consumer's replacement at the shared local context address. This is actual pointer and control-flow continuity, not a supplied callback simulation or a claim that the two requests are independent.

## Selected record consumer

`0x3f10ac0` checks raw dword tag 2 first. That arm returns zero without replacing either local context. For other admitted results, it saves result `+0xe8` and `+0xf0`; the latter is the consumed quantity eventually returned. It then disposes of the first local context's previous container through the observed flat-free or tree-destruction path. After normal cleanup, it replaces exactly 56 bytes at that first context from result `+0xb0..+0xe7`. It passes the second local collection, result `+0xe8` and the whole returned record to `0x3ce15b0`, then returns result `+0xf0`.

This closes a state change previously hidden behind the consumer: the next request sees the replacement descriptor, and the caller's row quantity receives the resulting remainder. It does not prove the original caller-owned state is immutable: the request helper still receives the original owner, and descriptor copies alone do not prove disjoint backing allocations. `0x2c62820`, iterator internals, `0x3ce15b0`, tree destruction, allocation validity and helper unwind behavior remain explicit dependencies.

## Validation

The verifier binds 5 windows, 1,343 bytes / 296 instructions, 99 facts and 92 changed-byte controls to the complete artifact digest. Controls cover the mode gate, both request tags, exact forwarded quantity and pointers, result gates, subtraction boundaries, replacement source/destination, same-row write and consumer relocation. They establish reproducible instruction/dataflow evidence, not native runtime equivalence or a complete simulator.

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-007-node115-nonzero-portfolio-replacement/verify.py --target /path/to/original/hl-node
```

A future implementation can use this sequence as its integration contract after the request executor and secondary-collection mutation are independently reconstructed. No full component or backlog completion gate changes here.
