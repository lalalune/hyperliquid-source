# RE-001 / RE-003: two node #115 byte-fed entrypoints reject their first value

- Component: serialization/foundation; bounded entrypoint classification for offline fixture selection.
- Target #115: 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Question: do these short bodies provide a positive byte-sequence decoder witness merely because they reference five-element struct diagnostics and contain a tag-9 continuation?
- Observation/proof: under the observed byte-fed input form and normal ABI-preserving helper returns, their first-value chains produce tag 6, and their local continuation tests require 9. Empty input also reaches the tag-6 constructor. No positive decoding witness is established by these bodies.
- No oracle policy, complete codec, reconstructed Rust or progress gate.

## Exact scope

| Role label | Actual FDE half-open VA range | Bytes | Instructions |
| --- | --- | ---: | ---: |
| config byte-fed entry | `0x186d0f0..0x186d3a1` | 689 | 174 |
| change byte-fed entry | `0x18500a0..0x18503fc` | 860 | 201 |
| first enum expectation helper | `0x2751700..0x2751772` | 114 | 25 |
| first option expectation helper | `0x26502f0..0x2650362` | 114 | 25 |
| formatted carrier constructor | `0x18be120..0x18be1ba` | 154 | 46 |
| length-diagnostic helper | `0x17fbb40..0x17fbb9d` | 93 | 21 |
| enum expectation callback | `0x2773d10..0x2773d29` | 25 | 6 |
| option expectation callback | `0x26a1410..0x26a1429` | 25 | 6 |

Total: **8 complete FDEs, 2,074 bytes / 504 native-decoded instructions**.
All raw disassemblies, original FDE/CIE records, body hashes and coordinates are
retained. Role labels describe the observed relationships, not original symbols
or a recovered Rust calling API.

The entry labels come from referenced fat-string diagnostics:
`struct ReferenceOracleConfig with 5 elements` at `0x5cbd5d`, slot `0x641f450`,
and `struct UnvalidatedReferenceOracleConfigChange with 5 elements` at `0x5cb11e`,
slot `0x641f200`. Diagnostic pointer relocations, lengths and caller LEAs are
checked. This packet does not infer required input cardinality from that text.

## First-value path

The incoming RSI object is iterator-like: the selected prefixes load a cursor
from `+0`, an end pointer from `+8` and an item counter from `+0x10`. Valid buffer
geometry/nonaliasing and a finite counter are preconditions here; arbitrary
invalid pointers are outside the certificate. Both nonempty paths obtain an
unsigned byte with MOVZX and pass that scalar into their first helper.

- Config calls `0x2751700` at `0x186d16c`, then loads byte zero of its stack result
  and tests `AL == 9` at `0x186d17b`. A different value selects the propagation
  block `0x186d237`, which copies the carrier and writes that same tag to the
  output buffer's byte zero.
- Change calls `0x26502f0` at `0x18500f5`, then tests `AL == 9` at `0x1850104`.
  A different value copies the inner carrier to output `+8`, then stores the raw
  outer word 2 at `0x1850121`. This is an observed representation, not a claim
  about a concrete Rust Result/Option layout.

Config explicitly advances its incoming cursor and counter before the helper
call on the finite nonempty path. The change prefix has no corresponding store
through the incoming state pointer before its first helper. This is a statement
about local explicit stores, not a guarantee about all transitive/global effects.
Counter-overflow branches leave this normal-return certificate through an external
call; their behavior and unwind closure are not recovered.

Both first-value helpers have one call, one RET, and no local conditional branch.
They zero-extend SIL, record the value in a formatting argument, and call the
same constructor `0x18be120` with their original result buffer. The scalar's
0..255 value does not select a local success arm. Their different expected-type
objects are bound through actual vtable-like data relocations:

| Helper | Expectation object | Method slot / function | Constant bytes passed by callback |
| --- | --- | --- | --- |
| `0x2751700` | `0x643a5f8` | `0x643a610 -> 0x2773d10` | `enum ReferenceOracleMode` (24 bytes) |
| `0x26502f0` | `0x6436ad0` | `0x6436ae8 -> 0x26a1410` | `option` (6 bytes) |

The callbacks tail-call an opaque formatting method with those pointer/length
pairs. The raw descriptor at `0x44f07a` includes `invalid type:` and `expected`.
Complete rendered error strings, concrete trait names and the option's inner
type are not proved. No inferred source implementation is copied or used as an
oracle for the result.

## Why the normal carrier byte is 6

The constructor preserves the destination pointer in RBX. Its normal-return
block copies payload words, then executes `mov byte ptr [rbx], 6` at
`0x18be19d`, restores registers and returns at `0x18be1ab`. **The tag is a byte
in the supplied buffer, not a claim that RAX equals 6.**

The native-confirmed normal-call basic-block graph has three paths to the local
RET. Each crosses `0x18be19d`. A fourth path leaves this local analysis at the
allocation-failure call. Calls are treated as normal fallthrough only if they
return and preserve the declared ABI; unwind, allocator and indirect formatting
closure are excluded. The actual first-helper argument pointers are stack
addresses; the graph deliberately overapproximates the constructor's alternatives.

`constructor_graph()` derives the short-branch destinations from captured bytes.
The independent graph check removes the tag-store node and verifies that the
normal epilogue becomes unreachable from the entry. Native decoding independently
checks the complete branch/RET set, and checks that each first helper and the
length helper has no local branch and only its bound constructor call.

Thus, if the first helper returns normally, the caller reads 6 and the local
comparison with 9 cannot select its continuation. The claim covers every first
byte value by value-independent control/data flow, not by executing 256 captured
inputs. Empty/null cursor input instead selects the bound length helper, which
also calls the same carrier constructor; change wraps that carrier with word 2.
The invalid input-state/counter cases are not asserted to return normally.

These two selected entrypoints therefore provide negative input-form evidence
for an offline harness. Larger owners of the same diagnostics exist (including
`0x1a88450` and `0x1983790`); their admissible inputs are unclosed here. This does
not say that the named configuration types have no valid deserializers, and it
does not classify raw wire bytes, MessagePack or JSON as this internal input form.

## Reproduce and validation

Python 3.12.14, macOS arm64, GNU readelf/objdump 2.47.20260726. From repository root:

```sh
python3 -B tools/u8_rejection_static.py --output work/u8-rejection-check
# Compare all generated files against this packet, excluding README/manifest.
python3 -B -m unittest discover -s tests -p test_u8_rejection_static.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-001-node115-u8-rejection && shasum -a 256 -c MANIFEST.sha256)
```

The producer authenticates the entire capture before parsing/output, then gives
private byte-identical snapshots to native tools. Actual FDE endpoints, complete
body byte coverage and selected instruction starts are independently checked.
Text exports preserve UTF-8/LF bytes. Public entry rejects #94, truncated and
same-size modified snapshots before output creation.

Six focused tests cover retained/native regeneration, the three returning graph
paths, and real semantic counterfactuals: changing the carrier's 6 to 9, changing
a caller's comparison 9 to 6, and redirecting the actual short jump to the
normal epilogue so the store is bypassed. These change the static certificate
before its checker rejects them; they are not executed or claimed valid typed
programs. Further controls corrupt 17 actual entry/call/propagation/expectation
instructions, six real relocation addends, three literal bytes and three FDE
extents below the public identity gate.

An initial control at `0x186d18a` was outside the certified failure path and was
not rejected. It was replaced with the actual failure-path output-pointer load
at `0x186d246`. This is not an all-byte corruption detector below the public hash
gate; it checks the explicitly stated obligations and the full public digest.

No captured executable/emulator, real configuration file, oracle update, signing,
wallet, network or chain action is used. Original captures/imports/source pins
and all reconstruction gates remain unchanged. Hosted CI, whole-codec equivalence,
all caller reachability and full helper/drop/unwind effects are not claimed.

Next question: bind the typed non-byte input owners and their first-value
acceptance before selecting a positive config-decoding fixture.

Observed local results: six focused tests passed in 38.314s; the required
`make doctor verify test catalogue-check` run passed all 437 tests in 181.821s
and completed the catalogue check. These are native local results, not hosted CI.
