# Conditional manual proof

## Domain and evidence boundary

Let `A` be entry RSI and `O` entry RDI at `0x4752890`; `S` is RSP after its
prologue. `word(P)` means the eight raw bytes at P read as little-endian u64.
Names associated with selectors come from PR #282; addresses and operand
roles below are checked against this capture. Objdump's nearest exported
symbol labels are not evidence of source function names.

Premises for the stated ordinary-return relation:

1. Entry is at the function start. Input, output, selected name spans, stack,
   TLS and helper-owned storage are accessible for the displayed operations;
   required outputs and live input/builder storage do not alias. No concurrent
   mutation or reentrant call changes that storage.
2. If `word(A)` has its top bit set, `word(A) XOR 2^63` is in `0..41`.
   Otherwise the selector is `0x27`. The table has no local bounds check, so
   arbitrary negative words are outside the proof domain. The scalar
   condition alone does not establish a valid source-level object.
3. Calls preserve the callee-saved registers and caller-owned live storage
   used after them. Allocations return suitable distinct storage on the
   successful paths; imported `memcpy` has the displayed copy behavior.
   Cleanup does not mutate a disjoint O. TLS initialization returns to its
   indicated continuation. These are external obligations, not conclusions
   inferred from relocation names.
4. Each claim is conditional on normal returns from the selected opaque
   calls. Allocation-failure/panic endpoints, traps and unwinding are outside
   the ordinary-return contract; no fallthrough from an allegedly nonreturning
   endpoint is used as a success path. Termination is not proved.

The collector authenticates the whole target, checks actual FDE extents and
`.eh_frame_hdr` links, then exports every byte in these ranges with GNU and
LLVM. It checks raw bytes and normalized instruction partitions independently.
The basic-block table is structural: calls retain a *conditional* return edge;
landing-pad instructions remain visible; LSDA edges are not fabricated.

| Role | Full FDE range | Bytes | Instructions |
|---|---|---:|---:|
| constructor | `0x4752890..0x4753d5f` | 5327 | 1025 |
| wrapper | `0x4aa70f0..0x4aa7351` | 609 | 133 |
| result-field | `0x49c0f10..0x49c10f6` | 486 | 108 |
| index-4aa7fc0 | `0x4aa7fc0..0x4aa825b` | 667 | 142 |
| index-4aa7810 | `0x4aa7810..0x4aa7aaa` | 666 | 149 |
| index-4aa6e60 | `0x4aa6e60..0x4aa70e6` | 646 | 140 |
| index-4aa8bf0 | `0x4aa8bf0..0x4aa8e51` | 609 | 133 |
| index-4aa89b0 | `0x4aa89b0..0x4aa8be3` | 563 | 117 |
| index-4aa95b0 | `0x4aa95b0..0x4aa9811` | 609 | 133 |
| index-4aa7ab0 | `0x4aa7ab0..0x4aa7d4b` | 667 | 142 |
| field-finalizer | `0x4ec13f0..0x4ec15d7` | 487 | 101 |
| insert-context | `0x47affd0..0x47b01ab` | 475 | 124 |
| builder-cleanup-context | `0x4735cd0..0x4735e1b` | 331 | 100 |
| allocator | `0x54c06b0..0x54c0772` | 194 | 37 |

`builder-cleanup-context` has two transfers not resolved by the deliberately
small CFG decoder: `call r12` at `0x4735d74` and a RIP-indirect tail jump at
`0x4735d98`. Manual reading connects the former to the slot load at `0x4735d41`
and the latter directly to slot `0x576e010`; no callee lifetime proof follows.
All other selected range transfers have structurally recorded targets or
returns/traps. A transfer census is not a proof of all dynamic reachability.

## Selector and complete outer partition

At `0x475289e`, R14 becomes A. `0x47528a1` puts
`T3 = 0x8000000000000003` in R12. `0x47528ab..0x47528be` reads `word(A)`,
XORs it with `T3-3`, and chooses that result only if the word is negative;
otherwise EAX is `0x27`. `0x47528c2` saves O in RBX. The signed 32-bit table
at `0x6f9b9c` is base-relative and feeds the indirect jump at `0x47528d3`.
All 42 table entries are decoded instruction starts within the full FDE.

| Construction | Selectors (hex) | Established outer result |
|---|---|---|
| Direct name (19) | 02,04,05,07,08,09,0a,0b,0d,11,12,14,18,19,1a,1b,1d,1e,1f | T3 and a cloned literal span in the active first 32 bytes |
| Ordered fields (12) | 00,03,0c,0e,0f,15,16,22,23,24,26,27 | First nonzero field return becomes T5/payload; all-zero field returns delegate the 96-byte builder |
| Explicit-index helper (11) | 01,06,10,13,17,1c,20,21,25,28,29 | O and A+8 handed to one of seven helpers; final O is that helper's result |

The byte checker binds all entries, direct-store encodings, field operand
setups, keys/call targets and the 11 helper targets. The path/def-use reasoning
is manual; the checker does not evaluate x86 instructions or prove source ABI.

## Direct-name stores

Each direct arm first calls slot `0x576dfd8` with the fixed literal length in
EDI and tests its returned pointer. Its successful path copies a literal name
using immediate stores and/or RIP-relative vector loads. The captured stores
then put `T3` at `O+0`, length at `O+8`, the allocated pointer at `O+16`, and
length at `O+24`. `contract.json` records each length and exact start of the
four output stores. All reach `0x475399e`, which returns O.

Shared tails matter: selectors 04/05 converge at `0x4753372`, then use the
length-15 tail at `0x4753482`; 0d and 19 also use that length-15 tail. 09/0a
share `0x475353d`; 0b/11 share the output stores at `0x47532ba`. The full CFG
includes these joins, so counting table-entry slices alone would be unsound.
The allocation-failure branches lead to `0x4753a50..0x4753b5a` calls and are
excluded by the successful-allocation premise.

**Nothing in these stores initializes O+32..O+71.** Later 72-byte machine
copies can carry inactive/stale bytes. Neither a 72-byte fully initialized
source value nor their semantic irrelevance is established here.

## Ordered-field arguments and result

Each of these 12 arms allocates/copies its variant name, calls `0x4ec15e0`
with EDI=0, requires its returned pointer nonzero, copies 16 bytes from that
pointer and increments its first word. It builds a 96-byte object at `S+0x10`
using the name triple, local constants and that copied pair. The helper's
identity and meaning are not inferred from this initialization.

For each row below, RDI points to this builder; RSI/RDX are the literal key
span; RCX is the indicated input address. Offsets are pointer arguments,
**not recovered field widths or Rust types**. R14 stays A until the displayed
final `add r14,offset`, or stays A for the three-field 0x27 path. The
callee-saved-register premise is needed between calls. Operand bytes,
RIP-relative key targets, key lengths/content, and E8 destinations are in
`contract.json`; perturbing a claimed offset is separately rejected.

| Selector | Prior name lead | Ordered fields: key, input pointer, helper (call site) |
|---|---|---|
| `0x0` | Hardfork | `hardfork` @ `A+0x8` → `0x49c0bc0` (`0x4752973`); `expected` @ `A+0x18` → `0x49c0bc0` (`0x4752999`) |
| `0x3` | BadBlockRound | `block_round` @ `A+0x8` → `0x49c1ad0` (`0x475319f`); `last_commit_round` @ `A+0x10` → `0x49c1ad0` (`0x47531c5`) |
| `0xc` | BadBlockProposer | `proposer` @ `A+0x8` → `0x49c1740` (`0x4752f1e`); `expected` @ `A+0x1c` → `0x49c1740` (`0x4752f44`) |
| `0xe` | DuplicateBlockRound | `known_block` @ `A+0x8` → `0x49c0d70` (`0x4752d9d`); `new_block` @ `A+0x20` → `0x49c0d70` (`0x4752dc3`) |
| `0xf` | TimeoutRoundMismatch | `round` @ `A+0x8` → `0x49c1ad0` (`0x47530c3`); `expected` @ `A+0x10` → `0x49c1ad0` (`0x47530e9`) |
| `0x15` | ClientBlockQcRound | `round` @ `A+0x8` → `0x49c1ad0` (`0x4753426`); `expected` @ `A+0x10` → `0x49c1ad0` (`0x475344c`) |
| `0x16` | ClientBlockQcHash | `hash` @ `A+0x8` → `0x49c07e0` (`0x47536b6`); `expected` @ `A+0x28` → `0x49c07e0` (`0x47536dc`) |
| `0x22` | ValidatorIPMismatch | `validator` @ `A+0x12` → `0x49c1740` (`0x4752c75`); `node_ip` @ `A+0x8` → `0x49c09d0` (`0x4752c98`); `expected_ip` @ `A+0xd` → `0x49c1540` (`0x4752cbe`) |
| `0x23` | AddTxDuplicate | `tx_hash` @ `A+0x9` → `0x49c07e0` (`0x4752a82`); `existing_from_rpc` @ `A+0x8` → `0x49c1420` (`0x4752aa8`) |
| `0x24` | AddTxCommitted | `tx_hash` @ `A+0x9` → `0x49c07e0` (`0x4752b5e`); `existing_from_rpc` @ `A+0x8` → `0x49c1420` (`0x4752b84`) |
| `0x26` | TxUnexpectedBroadcaster | `tx_hash` @ `A+0x8` → `0x49c07e0` (`0x475395d`); `broadcaster` @ `A+0x28` → `0x49c1740` (`0x475397f`) |
| `0x27` | TxInvalidBroadcasterNonce | `tx_hash` @ `A+0x18` → `0x49c07e0` (`0x475378c`); `broadcaster` @ `A+0x38` → `0x49c1740` (`0x47537af`); `err` @ `A+0x0` → `0x49c0d70` (`0x47537d1`) |

Each nonfinal field return is tested immediately; nonzero branches to
`0x4753989`, skipping the remaining fields. Each final return reaches the
shared test at `0x4753984` (the 0x26 path falls into it). On nonzero RAX:

- `0x4753989` writes RAX at O+8.
- `0x475398d..0x4753991` adds 2 to T3 and writes
  `T5 = 0x8000000000000005` at O+0.
- `0x4753994..0x4753999` passes the builder to `0x4735cd0`, then returns O
  through `0x475399e`, under the cleanup preservation/return premise.

When all field calls return zero, `0x47539b0..0x47539f6` copies all 96 builder
bytes to `S+0x70`. `0x4753a03` calls slot `0x5775300` with RDI=O and RSI at
that copy; its captured RELATIVE binding is `0x4ec13f0`. The caller thereafter
returns O without interpreting the helper result.

The full finalizer FDE confirms its boundary: `0x4ec1467..0x4ec14a4` consumes
the name triple plus remaining 72 bytes, calls `0x4ec08c0`, `0x4ec3730` and
`0x4ec16f0`, and `0x4ec153f..0x4ec1568` copies a local 72-byte container to O.
Those callees and the 26 field callees are opaque here. The packet does not
claim the returned map's source type, insertion semantics, error exclusion,
field encoding, or complete cleanup/ownership behavior.

## The 11 index/helper paths

PR #282 already recovered their ECX index/name setups. All 11 outer arms here
save A+8 as the seventh stack argument and pass O to the checked direct target.
They do not inspect the returned representation before the common O return.
Full selected helpers show the following raw inner construction before a
name-keyed 72-byte container handoff:

| Helper | Selectors | Concrete inner step |
|---|---|---|
| `0x4aa7810` | 01,13,20 | Load payload span pointer at Q+8 and length at Q+16, copy it; `0x4aa7928..0x4aa7933` writes T3/length/new pointer/length at O+0,+8,+16,+24 |
| `0x4aa89b0` | 28 | Load `word(Q)` at `0x4aa8a80`; write `0x8000000000000002`, zero, loaded word at O+0,+8,+16; other bytes are not established |
| `0x4aa6e60` | 10 | Zero a 42-byte scratch span, call `0x4ad9a40` at `0x4aa6f4c` with RDI=O, RSI=scratch, EDX=42, RCX=Q, R8D=20 |
| `0x4aa7ab0` | 06 | Zero 66-byte scratch; call `0x4ad9a40` at `0x4aa7bb1` with EDX=66, RCX=Q, R8D=32 |
| `0x4aa7fc0` | 17,1c,25 | Same 66/32 argument shape, call at `0x4aa80c1` |
| `0x4aa8bf0` | 21 | Call `0x4aa3b70` at `0x4aa8cba`, RDI=O, RSI=Q |
| `0x4aa95b0` | 29 | Call `0x47bb150` at `0x4aa967a`, RDI=O, RSI=Q |

Here Q is A+8. The last five helpers test the produced first word against T5.
Equal propagates the existing O after conditional cleanup of the cloned name
and local container. Unequal copies 72 bytes and calls `0x47affd0` with the
cloned name triple and copied value; afterward they conditionally clean a
returned temporary and copy the local 72-byte container to O. The first two
helpers use that same name/container handoff after their explicit raw stores.
No field wire format, integer signedness, text format, or complete map behavior
is inferred from these calls.

### Where the explicit index stops being a local operand

All seven helper FDEs contain no local use of entry RSI, RDX or RCX before
those registers are replaced. In the 66-byte helper `0x4aa7fc0`, for example,
RSI becomes the name pointer at `0x4aa8069`, RDX the name length at
`0x4aa806c`, and RCX the payload pointer at `0x4aa80be`; the converter therefore
receives Q, not the ECX case index. Other helpers replace RCX for their
converter or container call. The explicit stores above do not store that index.

This is a **local operand statement**, not global index noninterference:
TLS initialization, allocation and imported memcpy are calls before RCX's
local replacement. An opaque prelude callee can observe incoming registers.
The selected allocator `0x54c06b0` tests size against 4096; for the selected
name lengths (at most 32), its local path overwrites RCX at `0x54c06cc` before
later branches/fallback. The >4096 path reaches `0x54be8f0` before this write,
and TLS/import dependencies are still opaque. Neither argument nonuse in one
body nor the symbol `memcpy` proves absence of effects throughout that closure.
**No bincode index or wire bytes are proved.**

## Confirmed downstream consumer and upstream branch

The full `0x4aa70f0..0x4aa7351` FDE provides a concrete use, independent of any
source enum name. Its seventh stack argument is loaded at `0x4aa718e`; after
cloning the R8/R9 name span, `0x4aa71b4..0x4aa71ba` calls the constructor with
RDI=O and RSI=that argument. At `0x4aa71c9`, it compares word(O) with T5:

| Condition | Subsequent operation and result |
|---|---|
| word(O)=T5 | Conditional name/local-vector cleanup at `0x4aa71ce..0x4aa71ff`; O is preserved and returned at `0x4aa72e2` under the disjoint-cleanup premise |
| word(O)≠T5 | `0x4aa7204..0x4aa7237` copies exactly 72 bytes from O; `0x4aa7257` calls `0x47affd0` with the local container, cloned name triple and copied bytes; after a returned-temporary T5 check/conditional `0x4a0eb50`, `0x4aa72b7..0x4aa72df` copies 72 local-container bytes to O, then returns O |

The full `0x47affd0..0x47b01ab` context FDE reads the key's pointer/length,
calls `0x4778060` twice, copies its 24-byte key and 72-byte value arguments,
and calls `0x44e4350` at `0x47b0195`. This substantiates the handoff sizes;
the hash/map implementation and returned-temporary source type stay unresolved.

The full `0x49c0f10..0x49c10f6` FDE consumes a field key and an input pointer A:

- `0x49c0f83..0x49c0f8b` compares word(A) with `T5+0x25 =
  0x800000000000002a`.
- Equal: A+8 is the seventh argument of `0x4aa6e60` at `0x49c0fa7`, with
  literal bytes `Ok` (`0x70f7c0`, length 2).
- Unequal: A unchanged is the seventh argument of `0x4aa70f0` at
  `0x49c0fc4`, with literal bytes `Err` (`0x70f7c2`, length 3). This is the
  confirmed path into the constructor; it is not a handoff from `0x44adfa0`.
- At `0x49c0fc9`, temporary word=T5 selects its +8 payload; after conditional
  cloned-key cleanup, that payload returns in RAX.
- Otherwise it copies the 72-byte temporary, passes the original builder+0x18,
  key triple and copied value to `0x47affd0` at `0x49c1054`, conditionally
  cleans the returned temporary, and returns RAX=0 at `0x49c10b7`.

This gives a useful result convention to a downstream caller: construction
failures propagate a raw payload instead of entering the name/container path.
The `Ok`/`Err` bytes are evidence; a Rust `Result<...>` type identity, validity
of every possible input, semantic source enum match, and complete nested
ownership are not consequences of those bytes alone.

## Verification boundary and unresolved work

Selected RELATIVE records require **type 8 and symbol index zero**, plus their
fixed addends: `0x576dfb8→0x1346068`, `0x576dfd8→0x54c06b0`,
`0x576e010→0x54c8cb0`, `0x5775300→0x4ec13f0`. Slot `0x576dfe0` separately
requires GLOB_DAT type 6, symbol index 6, zero addend and undefined function
symbol `memcpy`. These are captured bindings; live relocation/interposition
and runtime helper behavior are not tested.

The 281 controls run below the whole-image SHA gate where applicable: fixed
instruction/data witnesses, all selected relocation addends/symbol indexes,
FDE ranges, unwind-header encoding, LSDA call-site bytes, every distinct field
operand witness, all 26 claimed input offsets, direct output stores, truncated
or changed native rows, and output preservation. Two full regenerations check
all retained native exports, compact CFG and records. They validate evidence
integrity and decoder agreement, not the manual semantic argument itself.

LSDA call-site tables are retained separately from normal CFG edges. Action
and type chains, exceptional reachability, runtime unwinding and destruction
are not interpreted. Existing prior formatter/type associations remain leads.
Next work would need to close selected field/converter/map helper contracts
and find an independently evidenced wire serializer before claiming a source
schema or wire enum index. No captured execution or instruction evaluation is
used to fill those gaps.
