# RE-012: node115 gossip request consumer

- Component: node-runtime; supporting RE-005 serialization.
- Target: Linux x86-64 node115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Reference: main `05bc2de303c05525b71e7e257426e741bc66a390`.
- Contribution: static research. No Rust implementation or acceptance gate.
- Question: where does the decoded GossipRpcRequest go, and what does its
  two-u64 request actually check and read before it constructs a response?

The existing request decoder establishes tags0,1,2 but leaves the consumer
open. This packet follows its real caller to the synchronous handler. It
separates the range operation from peer-list and cached-status requests, binds
the seven native error outcomes, and identifies the actual quota/cache effects
that a future implementation must preserve. This is a requested RE-012 unknown,
not a reproduced application defect or a new protocol feature.

## Path and attribution

Addresses are link-time ELF virtual addresses, before load bias. Ranges in
[records.json](records.json) are complete half-open FDE extents, not a claim that
unwind coverage proves semantic closure. No target instruction was executed.

1. Existing decoder `5aac6a0` returns the request through
   `4e4a1e0..4e4a738`. That wrapper has three aligned decoder calls and reader,
   cursor, tracing and drop paths. It does not consume the request fields.
2. `5860970..5860a8a` wraps that decode with duration observation.
3. The async poll `5a60a50..5a61e38` calls it at `5a6146e`, copies the
   decoded tag/values, then calls the handler at `5a61539`.
   Its slot `64ebfb0` has an actual R_X86_64_RELATIVE relocation to `5a5dbc0`.
   Retained Location records bind `node/src/gossip_rpc.rs:107:38,130:80`
   and TCP read/write source paths. These are exact pointer/length/line/column
   records, not nearest-string attribution.
4. Handler `5a5dbc0..5a5e281` receives output in RDI, shared context in RSI,
   IPv4 word in EDX, and decoded request pointer in RCX.

Prior work is input, not new credit: the main request decoder/PR2414;
`RE-001-node115-gossip-peer-status-report` for `4fac310`;
`RE-001-node115-rate-limit-coordinates` for corrected bucket-helper coordinates.
Open PR2790 recovers ClientBlocksError *wire decoding*. PR2784 and PR2795
recover response payloads. This packet does not replace their codecs.
Main contains no prior semantic mapping of this handler; the integration census
lists the address but does not establish the request contract.

## Observations

### Dispatch

The qword request tag is tested at `5a5dbd4`. Tag0 enters the two-u64 range
operation. Tag1 calls the existing peer snapshot helper and writes native
output tag4. The other valid decoded tag2 copies48 bytes of cached state under
a byte lock. It does not call the peer collector.

Only0..2 are justified by the existing successful decoder. Other comparisons
in the enclosing async state machine are not extra wire request variants.
The cached state includes its own native output representation; this packet
does not assign wire tags to its copied qwords.

### Range admission and cost

The first u64 is read from request+8, the second from request+0x10.
Call `5a5dc0e` checks peer membership through `4fac7e0`, whose key comparisons
use byte-swapped IPv4 words. Independently, the handler admits exactly
127.0.0.1,10/8,192.168/16 and172.16/12. The loopback comparison does not admit
all127/8. A nonmember outside these cases reaches error0.

For admitted peers, unsigned `second-first` must not borrow (error1) and must
be at most99 (error2). Only then is the inclusive cost `second-first+1`
passed to quota helper `59db3a0` with cap10000. Equal endpoints cost1.
The cap is a call argument, not proof that an exemption callback cannot bypass
accounting. The active IpAddr-shaped key bytes are tag0 and the IPv4 word;
unused bytes are not asserted to be zero or part of logical key equality.

The holder's byte lock surrounds clock/bucket/quota operations. Calendar and
subsecond arithmetic forms a millisecond-like clock value, clamps nonpositive
values to zero and divides by holder+0x170. A larger quotient advances the
saved bucket at+0x178; equal or older quotients do not. Initialization, a
nonzero divisor and the clock provider's complete contract remain premises.

The new-bucket flag is passed to `5617370`. That helper is not merely an
optional metrics sink: when the flag is1 it invokes `59db990` first.
The latter clears the item counts/control bytes of quota maps at+0x128,
+0x170,+0x1d0,+0x1a0, retaining allocations, and invokes aggregate/log handling.
It may invoke `5b98500` before clearing secondary maps. That helper's reporting
effect is still open. It must not be replaced with an invented no-op.

`59db3a0` has a real register callback, map-entry lookup `4ef76e0`,
saturating usage/request counters and secondary warning/timestamp maps.
A nonzero result becomes error3. Callback binding, full hash/key equality,
secondary-map reporting and logging behavior are not reconstructed here.
There is no claimed complete Boolean rate-limit implementation.

### Cache and native results

After quota admission the handler locks the separate cache. It supports
tree and flat ring representations. No available first/last record is error4.
The selected first block's floor is compared with the requested lower endpoint:
`lower <= floor` is error5. `upper > last_key` is error6. These comparisons
happen after charging quota. Rejected cache requests can therefore have already
updated quota state.

On success, the handler passes both endpoints and bound byte0 to `4dce320`.
For its flat24-byte rows, `57f2fb0` finds the first key >= lower and
`57f2c40` finds the first key > upper. The selected flat range includes equal
endpoint keys and may span both ring slices. `4e18c50` advances those slices
or the tree iterator; `5acca00` collects handles and increments both reference
counts. Tree allocation/layout validity and panic/unwind behavior remain open;
the flat comparison result is not used to assert complete tree equivalence.

Native outer tag3 holds the range result. Its next qword is a Result-like
success/error selector; the following words hold a vector or error payload.
The seven error indices are, in order:0 peer restriction,1 reversed endpoints,
2 excessive span,3 quota rejection,4 no cached blocks,5 lower floor,
6 upper bound. Indices1,5,6 carry pairs. Inactive error fields are not assigned
meaning. `5aaa0c0` is their Display formatter, not a response encoder. Its
exact-length literals include "Peer-only request", "rate limited",
"no client blocks to serve" and "too many client blocks requested".

## Reproduce and evidence

From the repository root, with the authenticated capture materialized:

```sh
python3 -B research/work-items/RE-012-node115-gossip-rpc-consumer/verify.py
python3 -B -O research/work-items/RE-012-node115-gossip-rpc-consumer/verify.py
# Regenerate a complete native export for any listed range, for example:
objdump -d -Mintel --insn-width=16 --start-address=0x5a5dbc0 \
  --stop-address=0x5a5e281 artifacts/node/115/hl-node
make doctor
make verify
make test
make catalogue-check
make reproduce
```

Collection used Python3.12.1, GNU objdump2.47 and Capstone binding5.0.7/
core5.0.1280 on Windows. Every retained GNU instruction byte partition was
compared with Capstone. The verifier needs only Python and the repository's
pinned ELF/FDE parsers. It rereads the target digest, complete FDE bodies,
GNU byte partitions, selected guard pins, call displacements, relocation
bindings and exact Location records. Seven negative controls change an extent,
remove a tail instruction, alter a guard pin, change a direct call target,
change a relocation callee, falsify a source Location and omit a call record.

The17 selected extents total15784 bytes/3575 instructions. These are a bounded
static record denominator, not reconstructed Rust bytes, whole-module
coverage or a semantic proof for every dependency. All calls in retained
context records remain classified as direct, relocation-bound or explicitly
unresolved register calls. No operand masks are applied.

`gnu/*.objdump` preserves GNU instruction records, including addresses,
bytes and disassembly text. The local filename/header is omitted; these are
not byte-identical full command stdout files. Original command streams remain
in operator evidence. Do not confuse that header omission with a code mask.

An initial six-helper collection ended as failed-leftover-child despite root
exit0. The supervisor terminated only its Job and confirmed zero owned
processes. The missing child identity/cause is unknown. That run remains
failed. A later independent, child-free revalidation checked the retained
exports against the target and both partitions and passed. A separate
single-root GNU export of `59db990` passed. The first packet replay exposed an
out-of-scope reference to the already published decoder; removing that
reference, while keeping all17 whole selected extents, fixed the packet replay.
These are analysis/packaging results, not target behavior runs.

## Limits and next step

No Rust has been implemented or built for this handler. No target execution,
network, socket, signing, chain action or provider call occurred. Full async
state validity, response serialization, cache object variants, quota callback
configuration, helper/reporting closure, system clock, allocator, lock and
unwind equivalence remain unproved. All92 component gates and registered
implementation byte comparisons stay unchanged. No catalogue edit is needed.

Next: bind the quota callback/configuration and `5b98500` report contract,
then establish cache object variants and actual response serialization before
implementing the complete handler. Do not substitute invented collections,
opaque mocked callbacks or formatter output for those contracts.
