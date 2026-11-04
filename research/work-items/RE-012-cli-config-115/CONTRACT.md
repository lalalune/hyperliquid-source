# Node115 observed CLI contract

Every current address and claim in this document is bound to SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The actual CIE/FDE intervals, complete bytes and GNU/LLVM/Capstone instruction
boundaries are checked. Nearest dynamic-symbol annotations do not identify
these private functions. Historical node94 records are migration leads only.

## Domain and unresolved boundaries

`out` means entry RDI; `builder` receives an App-like value pointer in RSI,
with an observed 592-byte (`0x250`) copy span. `config` receives a parsed-state
pointer, and `commands` a descriptor of three qwords:
name pointer, byte length, child-argument pointer. These are observed register
and storage relations, not a recovered stable Rust ABI.

The normal-path interpretation requires mapped stable well-formed objects,
readable byte strings, disjoint output/input/stack/control storage, ordinary
allocator and memcpy contracts, and the stated helper calls returning
normally. It does not admit arbitrary pointer patterns, malicious helper
writes, concurrent mutation or all input/output aliases. Inactive union words,
stack padding and uninitialized payloads are not invented zero defaults.

`value(k)` denotes the actual call to `0x4e4ca30`, with the exact literal
pointer and length. Zero RAX means absent; otherwise RAX/RDX are the byte
pointer/length. `presence(k)` denotes AL from `0x4e4c8e0`. That helper first
compares the selected child name and then probes key membership. It does not
parse a string `"false"`. Both complete bodies are retained: hash
`0x4e52640`, bcmp import `0x64df9f8`, table construction/invariants and conversion
slot `0x64dfca8` are not recursively closed. Value lookup requires a nonempty
value list; conversion tag 1 goes to an error call. These names therefore do
not assert behavior on arbitrary malformed hash maps.

The record lists every call, unconditional jump and RIP reference in all
selected bodies, including register-indirect targets that remain unresolved.
It decodes LSDA headers and bounded call-site intervals, but not action chains
or arbitrary callee unwinding. Observing an error-call edge is not proof of its
text rendering, process exit, global effects or successful recovery.

## Root construction and licensed correspondence

`0x564d700` writes the literal `Reference implementation of Hyperliquid
protocol` and length 48 to input +0xb0/+0xb8 before copying 0x250 bytes.
It assembles two 0x210-byte Arg-like records in order, chain then key. Their
name pairs are at +0x180/+0x188, long-name pairs at +0x1d0/+0x1d8, flags at
+0x1b0, and validator allocation/vtable pairs at +0xb0/+0xb8. Chain's exact
five-byte literal is `0x92a7be`; key's three-byte literal is `0x92ab2c`.

Both start with raw flags 0x404. Chain receives 0x425; key receives 0x424.
The register-argument helper `0x1638840..0x1638fc3` tests bit 0x8 at
`0x1638854` and bit 1 at `0x16389b1`. Here bit 0x8 is clear for both, while
only chain reaches the required-name append (+0x1a8 vector, +0x1b0 count,
16-byte pointer/length element at `0x16389f8`). No root-global propagation
is inferred merely from where the options are attached.

Official Clap 2.34.0 commit `d51ae89656fda527ef1bccf53fca0ad78ecb8c29`
assigns EmptyValues=4, ValueDelimiterNotSet=0x400, TakesValue=0x20,
Required=1, Global=8. Its default is 0x404; its owned validator type is
`Fn(String) -> Result<(), String>` inside an optional Rc. This is a licensed
structural correspondence. The target instead embeds
`/home/ubuntu/hl/code_Mainnet/z_vendor/clap/src/...` at `0x43680d`,
`0x43ff99`, `0x446ca3`. It does **not** identify a Clap release. Official
2.33.3 has byte-identical argument flags and the same validator contract;
exact upstream version, vendor patches, dependency graph and build options
remain unknown.

For each validator, a 16-byte allocation via slot `0x64df480` is checked for
null and receives qwords (1,1). If a previous allocation pointer is nonzero,
its first counter is decremented, with last-strong cleanup through
`0x64e1d10 -> 0x1660100`. The constructed prior pair is zero. The chain/key
vtables at `0x64aac08`/`0x64aab18` have raw header (0,0,1) and three actual
RELATIVE method writers. Their target triples are respectively
(0x561fca0, 0x564df90, 0x564df90) and
(0x561fb30, 0x564e0f0, 0x564e0f0). No unique-to-key type claim follows from
shared callback entrypoints. All 33 primary-entry naming relocations are
recounted; overlapping or additional writers are rejected.

The temporary five optional-vector capacities are initialized to MIN64 at
stride 24. The complete 181-byte cleanup helper at `0x165b860` uses
NEG-overflow/zero for the first and explicit MIN64/zero tests for the next
four. They all skip deallocation for these initialized sentinels. This differs
from node94's emitted tests and is not a call to an initializing constructor.
Arg assembly copies 0x1d0 bytes plus explicit long-name and trailing fields;
padding and inactive words remain raw storage. Null validator allocation
reaches the layout/allocation error slot with EDI=8, ESI=16 and UD2 if it
returns.

After both registrations, slot `0x64ebcc0` calls the opaque factory
`0x564e1a0..0x56544a9` (25,353 bytes). On return byte +0x1e8 is ORed with
0x80. Public Clap associates that bit with SubcommandRequiredElseHelp, but
full parser/default/help behavior is not proved. The builder copies output
0..0x90 and 0xa0..0x250, then installs this exact 84-byte label at +0x90/+0x98:

`28076c144c66d3f34ca321ac85ca19f461ade137|2026-10-25 16:48:13 +0800|uncommitted=false`

The label is data, not authentication of a source commit, clean checkout or
reproducible build. Normal RAX is out.

## Owned validation callbacks

The chain validator takes the owned triple `(capacity,pointer,length)` at
entry RDX and a disjoint 24-byte result at RDI. Length 5 admits exactly `Local`;
length 7 admits exactly `Sandbox`, `Testnet`, `Mainnet`. Node115 uses immediate
ASCII dwords and a byte for Local, or overlapping dwords at offsets 0 and 3
for seven-byte values. All bytes are covered and comparisons are case-sensitive.
The successful result writes only MIN64 to out+0; the remaining 16 bytes
are unchanged. This is a Result-unit representation observation, not a chain
discriminant return.

Invalid text prepares `(0,1,0)`, requests 26 byte elements from
`0x5963a10..0x5963a9e`, copies the 26 bytes `Matching variant not found`
from `0x94a8dc` using overlapping 16-byte stores at +10 then +0, and writes
length to out+16 before the capacity/pointer block at out+0. For the supplied
zero-capacity request this reserve helper chooses max(8,26)=26 before calling
its opaque allocation adapter. The original input is freed on either normal
result when its reloaded capacity is nonzero; normal RAX is out. The reserve
call's LSDA interval `[0x564e02a,0x564e046)` reaches `0x564e0b4`, where any
error temporary is freed before original-input cleanup and UnwindResume.
The 5-byte once adapter `0x561fca0` tail-jumps to this body.

The key callback does not validate syntax. For positive valid length it
allocates, memcpy-copies and immediately deallocates the copy, then writes
MIN64 to out+0 and frees the original if its capacity is nonzero. Zero length
skips allocation/copy/free of the copy. A high-bit length reaches error EDI=0;
null allocation reaches EDI=1. The once adapter `0x561fb30` snapshots the
original capacity before the output store, while `0x564e0f0` reloads it after.
They agree under the disjoint valid-owned-input premise; arbitrary aliases
must not be equated. Only the explicit error-call interval has the local
original-input cleanup landing pad. The allocation/copy calls have no local
pad in this body.

## Configuration construction and two actual callers

At `0x564ccf7` the configuration extractor first looks up `chain`. An absent
value goes to Location `node/src/hl_node.rs` 22:12; a nonmatching value goes
to 21:5, before any key lookup or successful output store. Local/Sandbox/
Testnet/Mainnet produce stored bytes 0/1/2/3 respectively.

Only then is `key` looked up. Absent sets the capacity/length sentinel MIN64;
its inactive pointer register is not initialized. Present zero length uses
pointer 1. Other valid lengths allocate/copy that many bytes; high-bit lengths
and null allocations reach the observed error boundaries. This is ownership
construction, not key parsing or signing.

The selected child at parsed-state +0x48 supplies `(child[1],child[2],child+24)`;
null supplies `(1,0,0)`. Slot `0x64ebcb0` calls the command extractor.
Only its first **dword** is compared to 16 at `0x564ce5d`; equality reaches
Location 26:14. Otherwise the 120-byte command result is copied in descending
block order +0x70 (8 bytes), +0x60,+0x50,+0x40,+0x30,+0x20,+0x10,+0
(16 bytes each). Chain byte goes to +0x90 and key triple to +0x78/+0x80/+0x88.
Bytes +0x91..0x97 are untouched. Normal RAX is out. The selected command call
and missing-command error call have LSDA cleanup to `0x564cf0d`; twice the
saved key length modulo 2^64 decides whether deallocation is skipped for zero
or MIN64 before UnwindResume. No transactional failure policy is inferred.

The actual entry writers are builder slot `0x64e73c0` and config slot
`0x64e73c8`. Two instruction-verified caller FDEs contain both calls:

| Complete caller | Builder site | Config site |
| --- | --- | --- |
| `0x2b7b640..0x2b7b79c` (348 bytes) | `0x2b7b6ac` | `0x2b7b73f` |
| `0x2ae41e0..0x2ae6d66` (11,142 bytes) | `0x2ae42f5` | `0x2ae437a` |

Both construct `hl-node` from the seven bytes at `0x92a890` and call App
constructor slot `0x64e1d08`, builder, then parser slot `0x64e1da8`. The small
wrapper tests parser qword MIN64+1: error copies 56 payload bytes and writes
qword16; success snapshots 80 bytes, calls config, performs cleanup and copies
0x98 bytes into out. Both normal paths return out. The larger caller uses the
same parser error sentinel and later tests a full config qword against16;
its subsequent dispatch, asynchronous states, side effects, global/TLS values
and other embedded tables are excluded. Its complete bytes/FDE are context
for the two actual edges, not a whole-body behavioral claim or an exhaustive
runtime-indirect caller census.

## Selected command and active payload

`commands` rejects `(length-8) mod 2^64 > 18` before reading name bytes.
The signed-dword relative table at `0x928884` covers lengths 8..26. All 19
entries are actual instruction starts. Fourteen spellings are reconstructed
from complete overlapping immediate or SIMD chunks; zero-extended SIMD tails
also require zero padding in the constant. `spec.json` and `records.json`
contain each comparison, match successor, chunk and first-word store.
A null child after a name match, an unsupported length or an unknown name
stores only qword16. No successful path writes qword14.

All unmarked values below are required. `owned(k)` means value lookup followed
by length check/allocation/copy or the retained owned-string adapter. Each
missing/conversion failure precedes later actions on that path.

| Selected name | First qword | Ordered action and payload |
| --- | ---: | --- |
| delegate | 6 | validator through opaque 20-byte parser, wei inline u64 conversion, presence(undelegate); amount+8,20 bytes+0x10,AL+0x24 |
| staking-deposit | 7 | wei inline u64 conversion; amount+8 |
| send-signed-action | 5 | owned(action), triple+8 |
| staking-withdrawal | 8 | wei via 0x5655de0; amount+8 |
| check-reachability | 11 | owned(abci-state-fln), triple+8 |
| run-validator | 3 | output helper into out+8, then3 |
| print-address | 9 | no payload stores |
| translate-abci-state | 4 | owned(in-fln) then owned(out-fln); triples+8/+0x20 |
| compute-l4-snapshots | 13 | owned(abci-state-fln), owned(out-fln), presence(include-users), presence(include-trigger-orders); triples+8/+0x20,bytes+0x38/+0x39 |
| compute-referrer-states | 12 | owned(abci-state-fln) then owned(out-fln); triples+8/+0x20 |
| send-slack-alert | 10 | owned(msg), triple+8 |
| run-non-validator | 2 | output helper into out+8, then2 |
| approve-non-expiring-agent | 15 | no payload stores |
| change-validator-profile | 0 or1 | commission presence and fields below |

The run variants call slot `0x64ebcb8` -> `0x564d390..0x564d6d8` (840 bytes).
Node94's output helper was6,623 bytes. The old output-field map is not imported
or re-claimed here. Its internal behavior remains outside this packet.

Profile actions are ordered: required owned(abci-state-fln), optional node-ip,
optional name, optional description, presence(unjailed), optional
Boolean disable-delegations, optional u64 commission-bps, optional signer.
Successful node-IP conversion tests **bit0 of AL**, shifts RAX right8,
and retains its low dword. The called 104-byte adapter `0x15b1290` rejects
length > 15; otherwise it calls 0x167ccb0 and combines that helper's low byte
with whether the input descriptor has no bytes remaining. That transitive
IPv4 parser/grammar is not closed. Treating every nonzero RAX as an error
would reject successful nonzero payloads.

| Profile offset | Actual write |
| --- | --- |
| +0 | qword0 if commission absent, qword1 after successful present conversion |
| +8 | parsed u64 commission if present; inactive RBP otherwise |
| +0x10/+0x18/+0x20 | required abci-state-fln triple |
| +0x28/+0x30/+0x38 | optional name triple, MIN64 first word when absent |
| +0x40/+0x48/+0x50 | optional description triple, MIN64 first word when absent |
| +0x58 | node-IP presence byte0/1 |
| +0x59..+0x5c | node-IP payload dword; zero on the observed absent branch |
| +0x5d | AL from presence(unjailed) |
| +0x5e | signer presence byte0/1 |
| +0x5f..+0x72 | signer 20-byte payload when present; inactive scratch otherwise |
| +0x73 | disable-delegations byte true1/false0/absent2 |

Profile payload writes begin at 0x565599f; its first-word tag is written at
0x56559dc. Node-IP absent explicitly stores
RAX=0 to its saved payload, unlike other absent fields; do not generalize that
zeroing to absent names, description, commission or signer. The old node94
+0x6e node-IP and +0x58 unjailed layout is incompatible. For both two-string
commands, node115 now stores first triple, tag4/12, then second triple;
node94's compute-referrer-states had a different write order.

The inline amount/commission loops and263-byte withdrawal adapter accept
one optional leading `+` followed by decimal digits, including leading zeroes,
with checked u64 multiplication/addition. Empty input, lone `+`/`-`, nondigits
and overflow reach distinct prepared parse-error bytes: empty0,nondigit1,
overflow2. At fewer than17 digits, the maximum decimal value is below2^64.
Long loops multiply before the loaded-byte digit test; on multiplication
overflow they still classify that byte (digit=>2,nondigit=>1). This is relevant
for e.g. `18446744073709551616x`: overflow can precede the trailing nondigit.
No whitespace, minus sign or prefix truncation is accepted. Boolean conversion
is now inline: exact lowercase `true`/`false`; absent2; invalid reaches its
error boundary. Signer/validator share slot 0x64e0b88->0x150d640; result byte1
is an error, otherwise20 bytes are copied. Actual accepted address grammar
and dynamic error trait objects remain unknown.

Allocations and reads occur before later failures. The complete function
contains per-path cleanup and exception intervals, retained in the raw record;
there is no validate-all-first, atomic-output or arbitrary-throwing-helper
claim. The large command factory and parser still prevent a faithful whole
CLI Rust implementation. This packet supplies current-target structure and
failure boundaries without substituting a new invented public API.
