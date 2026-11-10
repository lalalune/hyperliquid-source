# RE-008: node 115 first consensus timeout from polling to output

The first timer in node #115 passes selector tag `0x8000000000000006`
through an outer dispatch to a saturating timeout counter, conditional message
construction and filtered queue output; an independent model agrees with
15,531 byte-interpreter cases and detects all 43 instruction mutations,
while cryptographic and runtime services remain explicit contracts.

- Component ID: `consensus`; task RE-008.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `a8616af9432b8d8517b2af677880e117b7c28ef3`.
- Claim status: byte observations and bounded independent model; protocol
  names and their relationship to votes are inferences, not recovered types.
- Scope: one first-timer event, its poll entry and post-event output path.
  Other event arms, complete runtime services, native execution and
  whole-node equivalence are excluded.

## Reproduce

Use the repository root, Python 3.12 and the authenticated artifact:

```sh
python3 tools/node115_consensus_timeout_flow.py --out research/work-items/RE-008-consensus-timeout-flow-115
python3 -m unittest tests.test_node115_consensus_timeout_flow
rustc --edition 2021 --test --crate-name consensus_timeout_model research/work-items/RE-008-consensus-timeout-flow-115/rust-model.rs.txt -o work/consensus-timeout-model-tests
work/consensus-timeout-model-tests
```

Run the manifest command from this item directory for the basename-only
manifest entries:

```sh
cd research/work-items/RE-008-consensus-timeout-flow-115
sha256sum -c MANIFEST.sha256
```

The generator reads ELF, FDEs, relocations and instruction bytes directly.
It uses the repository's `elf_index.py` and `fde_extents.py`; it does not
invoke other programs. The target is memory-mapped read-only after a streamed
SHA-256 check and is never executed. Each case is checked immediately.
The captured test run used Python 3.12.3 and Rust 1.99.1; 58 Python tests and
four separately compiled Rust tests passed. The Rust fixture test consumed 142
rows produced from interpreted target bytes. On the measured machine one
generator run took 48.04 seconds and 207,700 KiB maximum RSS.
The 58 Python tests also passed in an isolated directory containing the tool,
its two shared parsers and the test module, with no target artifact or
binutils in its PATH.

The following GNU objdump 2.42 commands independently inspect the cited bytes;
the generator and Python tests do not call or parse objdump:

```sh
objdump -d -Mintel --start-address=0x2cdcd41 --stop-address=0x2cdcd7d artifacts/node/115/hl-node
objdump -d -Mintel --start-address=0x2af7ed2 --stop-address=0x2af7ef6 artifacts/node/115/hl-node
objdump -d -Mintel --start-address=0x2e099fa --stop-address=0x2e09ad6 artifacts/node/115/hl-node
```

Representative observations from these windows:

```text
2cdcd57  cmp    BYTE PTR [rbx+0x18],0x1
2cdcd70  test   al,al
2cdcd72  jne    0x2cdcb63
2af7ed2  lea    rax,[r12+0x2]
2e09a01  inc    rax
2e09a0b  cmovne rbx,rax
2e09a3a  cmp    rbx,0x1
2e09a3e  jbe    0x2e09a4c
```

## Evidence

Addresses below are link-time ELF virtual addresses; extents are half-open
FDE ranges, which are unwind evidence and are not a complete function census.
The root `0x2af77f0..0x2af8bd3` has file offset `0x2af67f0` and body
SHA-256 `427127960a40d09aaf71aa648cfdece33894eb95f6eca673582da4997ff0d2d0`.
The source-location record at `0x64481d8` identifies
`node/src/consensus/state.rs:210:7`, reached from the invalid entry arm.
The instruction and location alone do not prove which source-level type
contains the poll.

The generated `evidence.json` binds eight FDE ranges, file offsets, body
hashes, jump tables, eleven relocation slots, outcome counts and the digest of
the ordered comparisons.
`instructions.tsv` contains complete decodes of the scoped smaller FDEs and
the 187 reached rows of the larger event handler. `handler-blocks.tsv`
summarizes distinct handler blocks, including unvisited alternatives; indirect
edges and exception edges are not a complete control-flow proof. The index's
next-start upper bounds are not used as body sizes.

### Entry and selection

The outer poll accepts byte 0 for its initialization arm and byte 3 for its
resume arm. Every other byte selects the panic-service call at
`0x2af7bad`; the test covers all 254 other byte values up to that service
boundary. Initialization copies `0xbd8` bytes to object `+0xca0`, then
copies the remaining `0xc8` bytes of the `0xca0`-byte input. It starts the
first timer, and starts the second when the helper at `0x2e1b5a0` returns
true. The latter compares a success-tagged 20-byte result to the 20 bytes at
state `+0xbc0`, and cleans up selected error variants. An additional state
preparation helper is a no-op contract in the joined fixture.

The lookup slot `0x64e86f0` has a type-8 relocation to `0x595cb30`, the
independently investigated proposer-selection target in the existing #115
proposer-selection work item. This binds the relationship as a binary fact;
calling its selected value a proposer remains dependent on that work's
interpretation. The fixture replaces that provider with a known response.

The selector at `0x2cdca20` chooses a starting arm in a nine-arm rotation.
For the two timer arms, bits `0x20` and `0x40` suppress already completed
arms. A timer is polled only when its enabled byte is exactly 1. A zero poll
result clears that enabled byte, sets its done bit, and returns the first or
second timer tag `0x8000000000000006` or `0x8000000000000007`.
A nonzero poll result is pending. If all examined arms are complete it emits
`0x800000000000000a`; if some are pending it emits
`0x800000000000000b`. All 256 poll-result bytes were covered for each
timer arm. Seven non-timer arms are masked in isolated selector cases; the
joined flow starts with the first timer arm.

At `0x2af7ed2` the outer jump table maps the first timer tag to
`0x8000000000000002`. The event handler `0x2e098e0` selects its arm at
`0x2e099fa` from that value. In the joined fixture, after processing this
event the next poll is supplied a pending result and the outer poll stores
state byte 3 and returns 1.

### Counter, message and timer state

The handler copies the supplied 12-byte time value to state
`+0xb9c..+0xba8`, increments the unsigned counter at `+0x8c8` with
saturation, and conditionally calls `0x2e154e0`:

| Previous byte at +0x8d0 | New counter | Calls to builder |
| --- | ---: | ---: |
| zero | 1 | 1 |
| nonzero | 1 | 0 |
| zero | greater than 1 | 2 |
| nonzero | greater than 1 | 1 |

The two tests are independent: the builder's own write of 1 at `+0x8d0`
does not cancel the second call when the new counter exceeds 1. Each builder
call emits a `0x178`-byte item with leading tag
`0x8000000000000002`. When state `+0x838` is not
`0x8000000000000001`, it emits a second item with tag
`0x8000000000000003`. The actual payload builders and storage-clone
helpers are contracts; generated payloads are synthetic and carry no
claim about a real signature or serialized message.

The timer restart consumes a seconds word and a nanosecond dword. It performs
wrapping-width addition, rejects the observed signed-overflow/sign condition,
and subtracts one billion and increments seconds when the resulting dword is
at least one billion. A signed overflow on that increment or a remaining
nanosecond value exactly one billion goes to the panic boundary. These are
raw instruction rules, including malformed dword inputs; they should not be
silently replaced by assumptions about a valid duration.

After the handler returns its output vector, `0x2317b10` filters and
compacts entries using `0x2e11140`. The latter obtains a set through a
contracted provider and searches a tree for the local 20-byte value in the
joined fixtures. Different per-item outcomes exercise both retained and
dropped messages. The outer loop either places the retained items into a
contracted queue chunk, or calls the item-drop boundary when the queue's
closed bit is set. The chunk storage, allocation, logging, clock, set
provider, signing and scheduler hooks are not reconstructed implementations.

### Inferences

The diagnostic source location, timer-shaped state, message flow and set
lookup are consistent with a consensus timeout producing vote-related work.
The original Rust type names, wire encoding and real cryptographic algorithm
are unresolved. The contract-generated bytes are deliberately not evidence
of any network message.

## Implementation and comparison

`tools/node115_consensus_timeout_flow.py` contains a byte interpreter and
a separately written model of the selected rules. `rust-model.rs.txt` is
independently authored Rust for the scalar entry, timer choice, local
identity predicate and timeout transition. It is stored as text to keep the
research packet within the allowed file paths; it is not a component Cargo
crate and has not been compared as a compiled code window.

| Comparison | Cases |
| --- | ---: |
| Selector, including raw poll bytes | 737 |
| Local identity predicate and error cleanup | 1,044 |
| Timeout handler and builder | 5,720 |
| Joined outer flow | 7,776 |
| Invalid outer entry states | 254 |
| Total, all matched | 15,531 |

The ordered comparison stream is summarized by SHA-256
`4948d3dcb0d4832c214f1068819009203f414269c6a3119245944a48082e5624`.
`controls.tsv` records 43 actual one-byte instruction changes, their
witnesses' entry classes and observed rejection or mismatch. Of the 43,
38 produced mismatches and five were rejected by the interpreter or a
contract; zero are claimed equivalent. Tests also exercise wrong
digests, malformed ELF input, invalid address ranges, bad instructions,
changed state and corrupted message bytes without needing the artifact.

Two fresh regenerations with different hash seeds and timezones, and with no
binutils in PATH, matched byte for byte. No normalization masks or
compiled-node byte-equivalence metrics are claimed.

## Results and limitations

The Python model returns state, message bytes, service calls, queue results
and cleanup observations for the stated fixture domain. It does not establish
the behavior of a real clock, scheduler, signature routine, state-preparation
helper, allocator, set provider, output channel or concurrent queue. A
successful allocation and a quiescent lock are fixture premises. Timer and
invalid-state panics are checked only to the panic-service boundary: Rust
unwinding, destructor ordering and allocation-failure recovery remain
unresolved. The selector's other seven arms and the handler's other event
types are also outside scope.

No full consensus milestone or whole-node gate is requested. The next question
is to resolve the preparation and message-construction service contracts on
this same first-timer path, including allocation failure and the unwind
landing pads, before using the projection as a complete consensus transition.
