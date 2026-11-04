# RE-010: node115 priority-bid consumer and ordered state effects

- Component: `action-dispatch` (RE-010), with shared balance/fee dependencies.
- Target: Linux x86-64 hl-node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Reference: main `05bc2de303c05525b71e7e257426e741bc66a390`.
- Claim: bounded static observations and labelled inferences. No Rust implementation,
  target execution, behavior-equivalence result, byte window, or gate change.

## Question and before/after evidence

The current display-name packet identifies `gossipPriorityBid` and selected
dispatch seeds, but does not recover its consumer and ordered state effects.
Historical PRs #558 and #2008 concern node94; their tags, native statuses and
stored IP prefix are not node115 evidence. Before this packet, a reconstruction
could incorrectly reuse a replacement/refund model or treat the reservation
helper as a read-only affordability predicate.

This packet binds the selected native arms to wrapper `0x285d2e0`, handler
`0x2c32660`, and state helper `0x28b5120`. It identifies a reservation write
followed by a debit, a slot state change that rejects a later bid in the same
unchanged slot, and the actual selected event-record cleanup path. These are
static findings on the authenticated base binary, not a reproduced runtime bug.

## Reproduce and evidence identity

From the repository root, with the retained LFS target materialized:

```sh
python3 -B research/work-items/RE-010-node115-priority-bid-consumer/verify.py
python3 -B -O research/work-items/RE-010-node115-priority-bid-consumer/verify.py
# Optional independent decoding, with Capstone available to this Python:
python3 -B research/work-items/RE-010-node115-priority-bid-consumer/verify.py --capstone
```

`records.json` gives the actual FDE records, body hashes, call census,
RIP-relative references, selected signed-relative table entries and name
relocations. `claims.json` pins 55 specific instructions. Each complete FDE
has an original `raw-*.objdump.txt` and extracted `instructions-*.txt`.
Coordinates are unrebased ELF virtual addresses, not file offsets or runtime ASLR
addresses. The verifier authenticates the whole target, pinned repository
parsers, actual FDEs, VA mapping, body digests, every instruction byte and boundary,
call encodings/relocations, selected table targets and names. It also checks that
extracted instruction records match the original GNU output.

Original collection: Windows x64, Python 3.12.1, GNU objdump (GNU Binutils) 2.47,
Capstone binding 5.0.7 / core 5.0.1280. GNU options for every range were:

```sh
objdump -d -j .text -Mintel --insn-width=16 \
  --start-address=<records.json start> --stop-address=<records.json end> \
  <authenticated artifacts/node/115/hl-node>
```

No operand normalization was applied. Original GNU headers retain the operator's
D workspace filename; a fresh export elsewhere has a different filename header.
The instruction comparator does not treat that header as code. Whole-target and
per-body hashes, not filenames, identify the input. Capstone and GNU partitioned
the same 16 FDE bodies into 4,020 instructions / 16,119 bytes. This denominator
is the listed bodies only; other arms in the two large dispatchers are context,
not recovered priority-bid semantics. These are two decoders of original code,
not a compiled Rust comparison or a whole-component denominator.

The original multi-process collection ended with child exit 0 but the Windows
supervisor reported `failed-leftover-child`, terminated only its own remaining
Job descendants, and confirmed Job active-process count zero. That run remains
failed; its leftover cause was not established. The same collection was not
retried. Subsequent separate, child-free verification reauthenticates the retained
outputs against the target; its result does not turn the collection run green.

## Observations

### Selected native dispatch and admission

At `0x2bda82d` and `0x2bdbb10`, the native tag is reduced by `0x86`;
`cmovae` selects that result, otherwise index `0x14`. For native tag `0xd6`,
index 80 selects `0x2bda963` via table `0x609f00`, and `0x2bdbcb6`
via table `0x60a360`. Their calls are respectively `0x2c16020` and
`0x285d2e0`; the former also forwards to the wrapper at `0x2c16327`.
This establishes this selected arm, not the valid domain of arbitrary enum
integers, external wire decoding, all references, or all dispatcher arms.
Three relocated `gossipPriorityBid` name entries are retained; index/name
attribution starts from the credited current display-name packet below.

Wrapper `0x285d2e0..0x285d437` reads slot from payload `+0x28`,
an option-like raw tag/value pair at `+0/+8`, and IP bytes at `+0x18/+0x20`.
In order it rejects slot >= `0x0ccccccccccccccc`; rejects an active low-bit
option with a value at/above that same bound; rejects IP length >=16; then
requires parser success and zero remaining bytes. Native error words are
`0x154`, `0x154`, `0x158`, and `0xbe`, with outer byte `0x0f`.
The active-option numeric error stores constant 1 at output `+0x18`, not
the rejected value. Handler success word `0x1a2` becomes outer byte `0x0e`.

Leaf parser `0x167ccb0..0x167d082` accepts four dotted decimal octets:
1--3 digits, each below 256, no multi-digit leading zero, no fourth digit.
It restores the input slice on failure. A suffix after the fourth octet is
left for the caller; this wrapper rejects that suffix. Its success value
packs the octets into the low-to-high bytes of the IPv4 word. No native
return padding, invalid option tags, or public Rust ABI is specified here.

### Handler gates and reservation/debit ordering

Handler `0x2c32660` rejects slot-storage niche `0x8000000000000000`
with `0x197`, then index >= state `+0x38f0` with `0x198`.
Slots are selected from state `+0x38e8` at stride 80. The two otherwise
unguarded calls `0x2c94f00` and `0x42320d0` consume temporary error
records. For the actual constant tags `0x197/0x198`, their comparison
chains reach the return paths at `0x2c950ba/0x423228a`; their unrelated
heap-owning variants are not invoked by those two selected constants.

The slot is passed to price `0x3be5790` via slot `0x64e6ac8`.
An active option and price above the supplied limit returns `0x18e`.
Affordability `0x3bf4fa0`, via `0x64e64a0`, checks selected record
words `A,B`: `B + price` must not wrap and must be <= `A`.
Missing selected values contribute zero. Failure returns `0x18f`.
Its container traversal and diagnostic branch are retained, not replaced
with a test callback or declared fully reconstructed.

On passing, the handler calls `0x28b5120` with descriptor
`{price, slot[+0x30], byte 0}`. That helper:

1. Calls `0x3bf4b00` via `0x64e5af8`. It first bounds the token key
   against ledger `+0x38`; quantity zero returns true without account lookup.
   Otherwise it selects the mutable record, checks the same nonwrapping
   `B + price <= A`, and **stores `B + price` into record `+8`**
   at `0x3bf4be1`. Failure returns `0x18f` before slot writes.
2. Descriptor byte zero stores slot qword `1` and price at slot `+8`.
3. Calls `0x3bfa910` with direction byte 1 and `r9=0`. On its
   normal subtract path it stores `A-price` before storing `B-price`.
   The optional ratio/scaling follow-up is bypassed by the actual zero `r9`.
4. Looks up/creates a token-keyed accumulator through `0x2dbaf90` and
   `0x24247b0`, then adds price. Overflow calls the diagnostic helper;
   if that helper returns normally, the continuation stores `UINT64_MAX`.
5. Constructs metadata/amount and an actor vector, calls the selected sink,
   then stores byte `1` at slot `+0x40` and IPv4 word at `+0x41`.
   Finally it returns `0x1a2`.

Under consistent successful lookups and ordinary non-diagnostic continuation,
steps 1 and 3 compose `(A,B) -> (A,B+price) -> (A-price,B)`.
The names total/held/fee accumulator are inferred from these operations and
callers; full type/units/container ownership are not proved. In particular,
zero quantity skipping reservation lookup does **not** make the whole bid a
no-op: later lookup/create, slot writes and other helper calls still occur.
There is no atomic rollback or absence-of-aliasing claim.

### Slot reuse and selected sink

Price entry `0x3be57a5` requires slot byte `+0` to be zero; otherwise
it returns `0x18c` before its time/price helpers. A successful bid stores
qword 1 there. Thus, without an intervening reset/aliasing mutation, a later
bid on that same slot reaches `0x18c`, rather than replacing/refunding a
previous bidder through this path. Slot rollover/reset behavior remains open.

At `0x28b52ed`, the constructed record tag is
`0x8000000000000014`. The actual relocation at `0x64e6ad0`
targets `0x3fbb2a0`. Its signed-tag reduction selects table index 20
at `0x7bf998`, landing at `0x3fbb38e`. This path releases the
record-owned allocation when its size/capacity word is nonzero, then the
20-byte actor-vector allocation. The body does not read its incoming
state/timestamp/profile arguments. All its RIP call slots, its register-held
callee loaded at `0x3fbb330`, and its tail slot bind to `0x635de30`.
Allocator/deallocator naming is an inference from the call shapes and inspected
allocator wrapper, not complete allocator recovery. The selected body is
cleanup-shaped; it does not justify inventing an emitting event callback or
claiming that the entire node never emits an event elsewhere.

## Reuse, unresolved work and comparison limits

Credit existing node115 packets:
- `RE-010-display-name-path-115`: name/switch seeds; fresh selected entries and
  consumer binding are supplied here. The open display-name implementation
  PR #2846 has different scope.
- `RE-014-price-core-115`: the price scalar suffix. Its time/metadata/rounding
  prefix remains unclosed here; the already-bid entry gate and its actual
  consumer/slot write are the additional binding.
- `RE-006-node115-argument-producers`: complete shared `0x3bf4fa0`
  predicate body; this packet adds its actual bid caller and mutable reservation
  counterpart, not new credit for rediscovering its address.
- `RE-001-node115-spot-record-update-order`: ordered `0x3bfa910`
  stores; the bid's direction=1, quantity and zero-r9 producer are bound here.

No source was copied from the unlicensed can1357 inference reference.
New verifier/docs are independently authored MIT work, with the author's prior
MIT packet verifier reused for structural integrity checks.

Unresolved: external decoder/serializer and option validity; complete account
and token container semantics, insertion/allocation failures and aliasing;
time/rounding prefix and actual zero-price reachability; profiling when
state dword 0 is 1; metadata helper; diagnostic/unwind behavior; slot rollover;
all other consumers, full source ownership and whole-ELF identity. The packet
does not claim helper closure simply because a complete FDE was exported.
The nine negative controls are evidence-record corruption controls, not target
behavior vectors or Rust-equivalence tests. Root required-command outcomes
and any unrun checks are reported with the final PR head in the PR description.

Next question: bind the slot reset/rollover writer and the price time/rounding
prefix before implementing a complete source-built bid transition. Keep all
component gates false.
