# RE-001: raw RPC-code classifier and result stores

- Component: foundation / HTTP support. Bounded question: which raw code words
  reach which numeric kind stores at candidate `0x15bb930`?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as a lead only.
- Status: instruction/table/store observations; RPC context is a reference-led
  interpretation. Original private names and full Rust types remain unresolved.

## Reproduce

Repository root with CPython 3.12.14 on Windows:

```sh
python tools/rpc_code_static.py --out work/rpc-code-94.json
python -m unittest discover -s tests -p test_rpc_code_static.py -v
python research/work-items/RE-001-rpc-code-classifier-94/export_disassembly.py
```

Verifier and tests use the standard library. The optional exporter uses Capstone
5.0.6, x86-64 Intel syntax; inspected Windows wheel SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
Captured code and networking never run.

The full classifier FDE `[0x15bb930,0x15bbb45)` is **533 bytes / 145
instructions**. A real caller excerpt `[0x161434b,0x1614386)` is **59 bytes / 8
instructions**. Thus retained scope is **592 bytes / 153 instructions**. The
caller's complete FDE `[0x1611910,0x1615281)` (**14,705 bytes / 2,525
instructions**) is decoded solely for instruction-boundary validation, not
claimed recovered. Raw FDE/CIE records, complete-body hashes and the original
16-byte jump table are retained. Addresses are ELF VAs; `.text` file offsets
are VA minus `0x1000`. No normalization masks.

## Raw code classification

The candidate saves ESI in R12D. Its table index is 32-bit wrapping addition
`EAX = R12D + 32603`. An unsigned comparison admits indexes 0..3 to the table
at `0x261458`; four signed relative displacements resolve to the following
handlers. Three jump to the common store block; the fourth falls through.

| Raw word interpreted as i32 | Numeric kind | Handler VA |
| --- | --- | --- |
| -32700 | 0 | `0x15bba5b` |
| -32007 | 1 | `0x15bba54` |
| -32600 | 2 | `0x15bba66` |
| -32601 | 3 | `0x15bba5f` |
| -32602 | 5 | `0x15bba6d` |
| -32603 | 6 | `0x15bba36` |
| All other u32 words | 7 | default through `0x15bba46` |

No normal classification path emits kind 4. This does not prove that no other
constructor or representation uses it. Names such as enum variant labels and
their source-language ordering are not assigned to these numeric kinds.

Wrapping addition is a bijection on u32, so indexes 0..3 have exactly four
preimages. The two explicit equalities are distinct from them. This partitions
the primitive domain into six singletons plus `2**32 - 6` default words; it is
an integer argument, not exhaustive native execution.

Tests compare the model with an independent numeric dictionary for the declared
**131,072** signed values -65,536..65,535, plus additional full-width boundary
words. Zero mismatches occur. Negative Python integers and words above u32 are
rejected by the model instead of silently asserting wider-number aliases.

## Actual caller and output observations

One raw direct-call candidate to this entry was found by scanning `.text` E8
displacements and validated at a real instruction boundary: `0x1614381`.
At `0x161434b` the caller loads **a dword** from `[RSP+0xd0]` into ESI. It passes
output `RSP+0x70`, a 24-byte header at `RSP+0x748` and another input at
`RSP+0x770`. This direct-call observation is not a census of indirect callers.

The callee stores the numeric kind as a dword at output `+0x30` and the original
R12D code at `+0x34`. It copies the RDX input's 24 bytes to output `+0x18`.
At output offsets 0, 8 and `0x10` it stores respectively
`1 + unsigned(R13 < 1)`, R13 and RBP, then returns the original output pointer.
These are raw store observations, not a portable Rust object declaration.

The RCX input first word `0x8000000000000005` bypasses an out-of-scope helper
and sets R13 to zero. Other paths serialize/allocate/shrink/drop data through
helpers before classification. Their full semantics, OOM/unwind outcomes and
field meanings are outside the model; no optional-data success is inferred
solely from a pointer or numeric tag.

The reference `base/http_client.rs` supplies a JSON-RPC-error interpretation
and an i64 code field. Its names, field types and source enum order do not
establish this original ABI. The captured ESI width and caller load also do
not prove how arbitrary JSON numbers are admitted, rejected or narrowed
upstream. No wider wire-code aliasing claim is made. No reference source is
copied or modified.

## Controls, checks and remaining work

Six focused methods pass. Real-capture corruptions cover wrapping bias, table
bound/condition, both singleton comparisons, signed table entries, handler
immediates, caller load/call, result offsets, FDE extent and input identity.
Make is absent, so required Makefile Python commands were run directly. Full
suite: **363 tests in 110.735 seconds; 7 failures, 16 errors, 21 skips**; all six
new methods pass. This independent main-based branch excludes unmerged #227.
Doctor reports missing native prerequisites. Eight artifact size/digest checks
pass before missing GPG stops signature verification. Imports reject the Windows
reference checkout (reserved `node/aux.rs`, hydrated LFS inputs retained);
catalogue fails on native backslash paths. Reproduce stops at artifact
verification. None of these failures is recorded as success.

No full Rust enum, upstream JSON number parser, caller state machine, allocation
or helper closure, binary build/equivalence, captured execution, network action,
hosted CI or progress gate. Next question: close number deserialization and the
data serializer before recovering a full typed error constructor.
