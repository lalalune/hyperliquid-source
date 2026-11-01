# Conditional native contract

Target: node94, SHA256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are linked ELF VAs; ranges are half-open. The 18 full FDE exports
in `observed/` contain 10,532 bytes and 2,495 normalized instruction rows.
FDEs describe unwind extents, not an automatic semantic theorem. The following
is a manual dataflow proof; collector pins preserve its critical witnesses.

## Contract and premises

For the selected pair `{u64 tag=1, payload pointer P}`, define
`V(x)` as one byte for 0..250, FB plus u16-LE for 251..65535, FC plus u32-LE
for 65536..2^32-1, and FD plus u64-LE otherwise. The byte string supplied to the
hash update is exactly:

```text
ASCII("Hyperliquid Consensus Payload")          29 bytes, no terminator
01                                             variant tag
P[0x38:0x4c]                                   20 signer bytes
V(u64(P+0x20))                                 hardfork version
V(u64(P+0x28))                                 hardfork start round
V(u64(P+0x30))                                 vote round
P[0:0x20]                                      32 block-hash bytes
```

The semantic names come from the concrete QC caller and existing typed component,
not strings alone. This is not a claim about a source struct ABI or padding.

Premises: tag1; readable live fields; valid stack/output/allocator storage; stable
payload values from measuring through writing; no problematic aliases among
payload, vector metadata, allocated bytes, stack temporaries and output; no foreign
mutation of these live regions; normal SysV callee-save preservation; normal
successful allocation, byte-copy and deallocation calls. Opaque timing calls also
must preserve live/escaped storage. A call with an apparently unused argument
cannot be assumed harmless. Ordinary-return reasoning excludes allocation failure,
panic, unwind and LSDA landing paths, invalid pointers/tags, races and liveness.
No captured instruction is executed or interpreted by this packet.

## Root and selected wrapper chain

The full root is `454c050..454c2ac`. It saves the input pair pointer at stack+0.
At `454c065` it requests29 bytes; the two overlapping16-byte stores at
`454c07c..454c091` copy exactly the literal at `6f605b` (the overlap agrees).
The13-byte literal `consensus msg` at `6f6078` is passed as a label to
`4b747d0` at `454c0ab`; EDX=0. It is not appended by the selected local path.

The entire wrapper `4b747d0..4b7496a` saves the input indirection, calls clock
`4ee3800` before and after `471ce30`, then difference helper `4ee3730`.
BPL=0 bypasses optional logging. Status8 copies the returned Vec triple to the
root's stack+150. Other statuses instead return an empty Vec and dispose error
fields; they are not silently treated as serialized bytes.

Full `471ce30..471d083` with EDX=0 branches at `471ce46` to `471cec1`,
calling `45873d0` at `471cec9`. Other instrumentation/TLS branches are outside
this selected route. The two explicit pointer loads across this chain yield the
original pair: `45873d0` reads tag at pair+0 and P at pair+8.

Full `45873d0..45878c2` uses signed32-relative tables `6f5e18` and `6f5e2c`.
Their five destinations are retained; only index1 is claimed. There is no local
bounds check justifying other integers. The first table sends1 to `45874f1`,
then size helper `47767e0` at `4587507`; the second sends1 to `45877c1`.
The measurement begins at1, accounting for the tag. On status8 the measured
count is allocated at `45875d0`, yielding cap=count, pointer, len=0.
The write route reads literal u32=1 at `209f84`, writes it through `4aa9ae0`
at `45877d2`, then calls `47766b0` at `45877ef`.
Status8 returns the Vec triple at `45877ff..4587813`. The selected leaves use
the Vec at configuration+10 and do not read its first two configuration words;
this is why no unproven interpretation of those words is necessary.

## Measurement, order and capacity

The complete measuring helper `47767e0..47768f7` adds20 at `4776806`, then
calls `4aaa230` for P+20/+28/+30 at `477681c/477683a/4776858`, then
`4aa9e20` for32 bytes at `477686f`. Each next step is gated by status8.

The entire writer `47766b0..47767d5` first adds38 to the payload pointer and
calls `4aa9e50` at `47766d0`. The helper's full118 bytes copy exactly20 bytes
(16+4) and increment Vec length20. Next, `47766e0/47766fe/477671c` load the
three u64 words; calls `47766ee/477670c/477672a` pass EDX=0 to `4aa9f80`.
The call at `4776745` passes the original P to full `4aa9ed0..4aa9f48`,
which copies32 bytes as two16-byte writes and increments length32. These are
five ordered operations; every non8 result branches to error propagation.
There is no normal path omitting signer or placing hash before the integers.

The complete u64 writer `4aa9f80..4aaa228` compares FB at `4aa9f8b`,
10000 at `4aa9fb1`, then the high32 bits at `4aa9ffd..4aaa004`.
It writes FB/FC/FD and2/4/8 bytes, respectively. EDX=0 bypasses the rol/bswap
at `4aa9fdb/4aaa027/4aaa064`; little-endian stores follow. Its complete
matching sizer `4aaa230..4aaa2cb` contributes1/3/5/9. Raw32 sizing is the
complete `4aa9e20..4aa9e4b`; tag1 follows the one-byte branch of full
`4aa9ae0..4aa9c86`.

Thus size=1+20+Vlen(version)+Vlen(start)+Vlen(round)+32 is56..80, so every
measurement addition fits. Inductively, before each write the remaining exact
allocation equals that write plus the suffix. Marker and payload subwrites also
fit. All growth calls to `454f5d0` in these leaves are unreachable under the
stable-value/disjoint-memory premises; no grow implementation is assumed.
The selected leaf normal returns all set status8, discharging the status gates.
Uninitialized inactive error bytes are neither read nor given semantic meaning.

## Concatenation and hash boundary

At `454c0b0..454c0f5` the root forms two triples, prefix first and serialized
payload second, and calls full `48454d0..484565a` with count2. It sums lengths
at entry+10, stride24, allocates that sum, and copies in entry order through
the imported memcpy slot `576dfe0`. The ELF dynsym entry6 names memcpy.
Total85..109 fits positive isize and allocation; exact remaining capacity
excludes the grow branch. No separator, lengths or label is inserted.

At `454c0f5..454c17d` the root zeroes the200-byte state and offset, sets
rate136 and delimiter/mode word1 (delimiter1, mode0). At `454c18f` it calls
update through RELATIVE slot `576e1d8 ->4f59a10`; it clones E0 bytes and calls
finalize through `576e1e0 ->4f59e40`, output length32 at `454c1bd`.
Selected RELATIVE records require type8 and symbol index0, not just an addend.

Full update `4f59a10..4f59e3a`, offset0 and length<136, XORs the remaining
bytes into the zero state and records offsetL. Its full-block permutation calls
are not reached. Full finalizer `4f59e40..4f5a13d` XORs delimiter1 at L
(`4f59ee7`), high bit80 at135 (`4f59f0a`), calls
`5777790 ->4f59480` at `4f59f14`, resets offset and copies the first32 bytes
at `4f5a02b`. L is85..109, so padding bytes are distinct and output32<136.
There is one permutation and no second squeeze block for this domain.
The root copies these32 bytes to output at `454c202/454c206`, then finishes
cleanup; output preservation through cleanup remains a stated call premise.

The full permutation `4f59480..4f59a02` is retained as context. Prior
RE-009-app-hash-builder-94 (README59..67,92) and RE-005-action-signable-94
(README105..114) already identify this shared core from the24 round constants,
rho offsets, rate, padding and tiny-keccak path. This packet credits that
identity inference. It does **not** newly prove a symbolic equivalence for
every permutation register/lane. The offline hash wrapper uses the existing
MIT `node94-action-signable::keccak256`; equality to the native final output
is conditional on that credited shared-core identification.

## Full concrete callers and prior counterevidence

Full QC caller `4758d70..47593a0` loads QC round from+28 and copies the
hardfork pair from+18; hash is QC+30. Votes have96-byte stride.
At `4758ee0`, it copies row signer20 to stack+78, hash32 to+40,
hardfork pair to+60 and round to+70. Pair(tag1,payload=stack+40) at+30/+38
is passed to the root at `4758f46`. Therefore signer is payload+38,
version/start are+20/+28, round is+30 and hash is+0. Later recovery at
`4759045` consumes the digest and row+18 signature; comparison
`4759056..4759085` uses the saved signer. Recovery itself remains opaque.
Full signing caller `454b020..454b168` independently forms tag1 and calls
the root at `454b054`, then passes the digest to signing helper `14a2710`.
No private key, signature generation or captured caller is executed here.

RE-008-block-admission-94 README109/stubs.tsv6 explicitly replaces454c050 with
SHA256 of fixture fields. RE-008-vote-timeout-path-94 also excludes digest bytes
(README10, tool STUBS), but README52 says the signer is outside signed bytes,
and tool GATES row7 says first0x38. The full signer-first writer above supersedes
that unsupported inference. Those old fixtures remain useful for their stated
control-flow scope and are **not** real digest oracles. This finding does not
establish a defect in `AdmissionAuthenticator`: it intentionally leaves
cryptography external and already receives a Qc containing the vote rows.

## Fixture derivation and verification limits

Before new Rust, `corpus.py` fixes783 cases: the9^3 crossproduct of
0,1,250,251,65535,65536,2^32-1,2^32,u64MAX; allzero/allmax; and individual bit
perturbations of each20 signer and32 hash byte. Preimages follow the field map
above, independently of the new implementation. Digest fixtures are newly
authored coordinate-grid Keccak equations with generated rho/round constants;
empty/abc known answers are also already present in the credited existing
component tests81/89. Neither these fixtures nor Rust tests observe target
execution. `PRE-RUST-FREEZE.json` records the immutable derivation receipt.

Static negative controls act below the full-image hash gate on field/branch,
literal, table, relocation and FDE witnesses; they establish checker sensitivity,
not semantic correctness by themselves. Complete native exports and manual
closure establish the stated conditional relation. The18-FDE denominator is
this packet's retained context, not whole-consensus or whole-node coverage.
No component gate is advanced.
