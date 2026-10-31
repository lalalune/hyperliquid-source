# RE-001: node #115 capacity guard and packed-permit step

- Component: network transport/foundation; bounded constructor/attempt interface.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Question: how does the constructor's guarded capacity become the state word consumed by the measured conditional CAS attempt?
- Observation/proof: the initialization-prefix guard passes raw capacities below `2^61`, stores `2*capacity` at object `+0x30`, and the other body tests that same word's bit zero / minimum two before proposing `word-2` in a LOCK CMPXCHG loop.
- This is a static preparation/conditional-step relation, not a complete IP policy, Rust semaphore implementation or concurrency guarantee.

## Measured scope

| Role | Actual FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| guarded attempt/provider wrapper | `0x4770f40..0x47710d9` | 409 | 101 |
| constructor-associated body | `0x47710e0..0x477165a` | 1,402 | 255 |

Denominator: **two complete FDEs, 1,811 bytes / 356 native instructions**.
The retained native exports cover every byte from each actual entry. Independent
GNU readelf confirmations, original FDE/CIE bytes, file offsets and body hashes
are in the packet. No comparison normalization mask is used and no Rust binary
match is claimed.

The source associations are the actual relocated Locations
`net_utils/src/ip_semaphore.rs:37:51` (`0x6496548`) and `:28:35` (`0x6496560`).
Their common path pointer, lengths, line/column and native LEAs are verified.
These identify bounded diagnostic ownership, not original function names,
complete type layouts, IP-address encoding or all callers. No inferred reference
source implementation is copied or used as an oracle.

## Constructor initialization prefix

The constructor copies incoming RSI, shifts it right by **61**, and branches
out of the initialization prefix when the result is nonzero. Over raw u64
capacities the guard-pass set is exactly `[0,2^61-1]`. This is a local branch
fact, not proof that the complete constructor returns for every admitted input:
allocation and downstream opaque calls can still fail.

On the observed normal allocation path a helper is called with size **56**.
The returned nonnull pointer receives two initial qwords of 1, selected zero
stores and the state word at **`+0x30`**. The source capacity is doubled with
`ADD R12,R12` and stored there. For every guard-passing capacity `n`:

```
initial_word = 2*n
0 <= initial_word <= 2^62-2
initial_word & 1 = 0
```

The zero stores at `+0x10` and `+0x19` overlap and cover the observed field
region; **padding is not claimed initialized**. The two initial words suggest a
shared-owner header but a concrete Arc/Rust ABI is not established here.
Other constructor fields, including an incoming value and a raw binary64 60.0
word in temporary state, are retained in native output but are not assigned a
cache/TTL/network meaning. Formatting, callback/spawn-like helper effects and
complete constructor-return behavior remain unclosed.

## State gate and conditional winning CAS

The attempt body obtains an owner through incoming RSI, performs the captured
owner-reference operations, and loads a qword from **owner `+0x30`**. Under valid
owner/buffer/calling-convention assumptions, its local state decision is:

| Observed word w | Local route |
| --- | --- |
| `w & 1 != 0` | flag gate; normal local failure output uses raw byte 0 |
| `w == 0` | empty gate; normal local failure output uses raw byte 1 |
| even `w >= 2` | propose `w-2` in LOCK CMPXCHG at the same `+0x30` |

The actual TEST mask is 1, minimum comparison is 2, and LEA displacement is -2.
On failed CMPXCHG, the JNE backedge returns to the flag/minimum checks. The
packet records this native loop and its exact destination, without claiming
fairness, absence of contention, termination or a whole memory-model proof.

**Conditional on that CAS winning**, the update is exact:

```
new_word = w-2       # no unsigned underflow on this route
new_word & 1 = 0
(w >> 1) - (new_word >> 1) = 1
```

Thus one winning step uses the same state encoding established by
the constructor. Capacity zero initializes the empty-gate state; capacity one
initializes word 2, whose winning step proposes word zero. The flag gate's role
label is not a recovered public error enum or proof of where another function
sets the flag.

Owner LOCK INC/DEC operations and the INC-following JLE cold path are preserved
in the raw export. Their overflow/lifetime policy is outside this theorem;
JLE is not interpreted as a separate read/comparison of a signed post-increment
memory value. No reference-count/concurrency safety property is asserted.

## Provider and follow-up boundary

After the winning step, `0x4770fe7` calls the opaque provider `0x4774c50` with
the measured object/key/context arguments and Source Location. A nonzero result
word selects raw output stores: owner word at `+0`, dword 1 at `+8`, provider
word at `+0x10` and provider dword at `+0x18`. A zero provider word copies its
byte into output `+8` and writes output qword zero.

That zero-result path subsequently uses a byte CMPXCHG at owner `+0x10`, then
calls **`0x5ce5310`** with `(owner+0x10, 1, owner+0x10)` before owner decrement.
These are actual call/argument observations, **not a proof that the earlier
state decrement is rolled back**. The helper and its cold path remain unclosed.
Raw output descriptions assume the selected helpers return normally and preserve
the observed ABI; partial stores before an exception are not a returned value.

The provider, follow-up and cleanup direct calls, the owner-drop/cold/helper
relocated slots, and both source slots are separately bound in `records.json`.
Complete provider/IP-map semantics, per-IP counts/expiry, key representation,
constructor callbacks, allocation, rollback and unwind closure are not recovered.

## Reproduce and actual counterfactuals

macOS arm64; Python 3.12.14; GNU readelf/objdump 2.47.20260726. From repo root with
materialized captures and native GNU tools on PATH:

```sh
python3 -B tools/ip_permit_state_static.py --output work/ip-permit-state-check
# Compare generated files with this packet except README/manifest.
python3 -B -m unittest discover -s tests -p test_ip_permit_state_static.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-001-node115-ip-permit-state && shasum -a 256 -c MANIFEST.sha256)
```

The producer authenticates the entire input before analysis/output/native calls.
Readelf/objdump receive private byte-identical snapshots. Exact body coverage and
selected instruction starts are verified; text is written as UTF-8/LF bytes.
Wrong-release, truncated and same-size modified captures fail the public identity
gate before output creation.

Six focused tests cover retained/native regeneration and boundary relations.
Four actual operand counterfactuals change their extracted mathematical relation
before rejection:

- SHR 61→62 lets raw capacity `2^61` pass the changed local guard.
- LEA -2→-4 changes eligible state 4's proposal from 2 to 0, consuming two
  abstract units instead of one.
- TEST mask 1→2 sends state 2 to the changed flag gate.
- Minimum 2→4 sends state 2 to the changed empty gate.

Further controls alter actual guard/retry displacements, state read/init/CAS
field offsets, initializer words, output/tag/follow-up operands, direct calls,
real relocation addends, source metadata and both FDE extents. These project
static bit predicates/equations, not a virtual CPU or a concurrent target run.
Below the full public digest this checks the stated obligations, not arbitrary
byte corruption or a whole node comparator.

No captured executable/emulator, real semaphore/thread/owner object, live IP
policy, process state, network, wallet/signing or chain action is used. Imported
inputs/code/pins and all progress gates are preserved. Hosted CI, complete
runtime equivalence and a completed transport component are not claimed.

Next question: close the provider and one-unit follow-up helper before asserting
per-IP admission, full rollback or runtime concurrent behavior.

Observed local validation: six focused tests passed in **13.718s**.
`make doctor verify test catalogue-check` passed **437 tests in 167.310s**,
all capture/import/source-pin/signature checks and catalogue consistency.
`make reproduce` passed. Packet manifest and staged whitespace checks passed.
No hosted-CI or captured-code execution result is claimed.
