# Observed construction paths and limits

All addresses below belong to target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Complete GNU and LLVM exports and Capstone rows are retained. FDE endpoints
come from actual CIE/FDE decoding, then the entire stated extent is decoded;
branch targets inside each extent must be instruction starts. This establishes
the observed bodies, not that no additional cold code or transitive helper
behavior exists elsewhere.
Disassembler nearest-symbol annotations are not used as function names or
source ownership evidence.

## Premises and vocabulary

`out` denotes the entry RDI destination; the two primary functions save it in
RBX and return it in RAX on their normal return path. The chain function takes
a parsed-state pointer in RSI. The command function takes in RSI a three-qword
descriptor: name pointer at +0, byte length at +8, child-argument pointer at
+0x10. These are register and memory observations, not a recovered Rust ABI.

The following normal-path interpretation assumes mapped, stable, well-formed
caller/table objects, valid buffers, ordinary allocator and `memcpy` contracts,
and the observed helpers returning normally. Output, stack/control data and
input/table storage are disjoint under this interpretation. Arbitrary pointer
bit patterns, input/output aliases, concurrent mutation and callback corruption
are not admitted. Complete raw instruction records remain available, but this
packet does not claim an all-memory-state behavioral model.

`value(k)` means the actual call to `0x452f5a0` with the exact key pointer and
length. RAX zero takes the absent branch; otherwise RAX/RDX are passed as
pointer/length. `presence(k)` means the AL result of `0x452f440`, not truthiness
of a string value. That helper first compares the selected child's name, then
checks backing-map membership. It does not parse `"false"` as false. Full helper
bodies are retained because this difference affects `undelegate`, `unjailed`
and the two include flags.

The lookup helpers probe 16 control bytes at a time, compare candidate key
lengths and call the imported `bcmp` slot `0x576e378`. The value helper further
requires a nonempty value list and calls slot `0x576e3f8` on its first value;
result tag 1 reaches an error call. Hashing at `0x473c350`, conversion, map
construction and table invariants are not closed. Consequently the names
"value" and "presence" are conditional interpretations of these instructions,
not proof of behavior on arbitrary supplied maps or invalid UTF-8.

## Chain precedes key and selected command

In `[0x4578bd0,0x4578e2a)` the first lookup is the five-byte `chain` key at
`0x6f6148` (call `0x4578bf6`). A zero return branches to Location line 21,
column 12 and call `0x4578dde` before a key lookup or output store.
Length is checked before string loads. Five bytes compare against `Local`;
seven bytes compare, in order, against `Sandbox`, `Testnet`, `Mainnet` using
overlapping dword loads at input offsets 0 and 3. Their constants occupy
`[0x26512f,0x265149)` and the resulting stored byte is respectively 0, 1, 2, 3.
The full width union covers every character; matching a prefix or a different
case is insufficient. An invalid value reaches the diagnostic setup at
`0x4578c6f` and call `0x4578c8e` (Location 20:5).

Only then does call `0x4578cab` look up the three-byte `key` at `0x6f614d`.
An absent value sets R15 to `0x8000000000000000`. A present value uses the
returned length: its high bit takes the allocation-layout error path, zero
uses pointer 1, otherwise slot `0x576dfd8` allocates the length and a null return
reaches the allocation-error call. The bytes are copied through `memcpy`.
The successful owned triple is `(length, allocation_pointer, length)`; the
absent sentinel does not initialize an active pointer. No key contents or
signing behavior were examined or exercised.

The child pointer is loaded from parsed-state +0x48 after this step. For a
nonzero child, `[child+8]`, `[child+0x10]`, and `child+0x18` supply the command
descriptor. A null child supplies `(1, 0, 0)`. Call `0x4578d4b` uses
`R_X86_64_RELATIVE` slot `0x5776a78`, addend `0x4583030`.
The returned first **dword**, not a full qword, is compared with 16 at
`0x4578d51`. Equality reaches call `0x4578deb`, Location 25:14, before stores
to the caller's output.

Otherwise output bytes +0..+0x77 are copied from the 120-byte command scratch
area. The actual block store order is +0x70 (8 bytes), +0x60, +0x50, +0x40,
+0x30, +0x20, +0x10, +0 (the latter seven are 16 bytes). Then the chain byte
is written at +0x90, and the key triple at +0x78/+0x80/+0x88. Bytes +0x91..97
are not written by this function. At `0x4578dc2` RAX becomes out.

Cleanup instructions at `0x4578e01` test twice the saved key length modulo
2^64; zero and the absent sentinel skip deallocation. Other lengths reach the
deallocator, then `_Unwind_Resume`. We record all these instructions and the
LSDA pointer, but do not decode the complete LSDA action graph or promise
panic/unwind behavior or transactional allocation failure.

## Selected command: complete normal dispatch map

`[0x4583030,0x4583f52)` computes `(name_length - 8) mod 2^64` and rejects it
when unsigned-greater-than 18. Thus admitted lengths are exactly 8 through 26,
without dereferencing the name on the rejected-length branch. The 19 signed
32-bit table entries at `0x6f5dcc` are relative to the table base. Each is
verified against an actual instruction start. Name tests use immediate qwords
or SIMD equality; overlapping loads cover the entire spelling, and short SIMD
tails compare zero-extended input with explicitly zero-padded constants.
The exact chunks and both comparison/matched-successor addresses are in
`records.json`. Following a name match, a null child-argument pointer also
branches to `0x4583580`, which stores qword 16. Unknown same-length names also
reach that store. No path writes successful qword 14.

`owned(k)` below means lookup followed by length checking, allocation/copy or
the equivalent adapter. All unmarked values are required: a zero lookup return
reaches its missing-value Location before the following action. The table is
in semantic action order, not physical instruction-address order; several
paths share out-of-line blocks. Offsets are from command `out`, and an owned
triple occupies three qwords.

| Exact selected name | First qword | Ordered actions and active payload |
| --- | ---: | --- |
| `delegate` | 6 | Required `validator` through the 20-byte parser, required `wei` through inline u64 conversion, then `presence(undelegate)`; u64 at +8, 20 bytes at +0x10, AL at +0x24. |
| `staking-deposit` | 7 | Required `wei`, inline u64 conversion; result at +8. |
| `send-signed-action` | 5 | `owned(action)`; triple at +8. |
| `staking-withdrawal` | 8 | Required `wei`, adapter `0x4584030`; u64 at +8. |
| `check-reachability` | 11 | `owned(abci-state-fln)`; triple at +8. |
| `run-validator` | 3 | Call output-configuration helper with destination out+8, then store 3. |
| `print-address` | 9 | Store 9; no payload store in this path. |
| `translate-abci-state` | 4 | Copy `in-fln` before lookup/copy of `out-fln`; triples at +8 and +0x20. |
| `compute-l4-snapshots` | 13 | `owned(abci-state-fln)`, `owned(out-fln)`, `presence(include-users)`, `presence(include-trigger-orders)`; triples at +8/+0x20 and AL bytes at +0x38/+0x39. |
| `compute-referrer-states` | 12 | Copy `abci-state-fln` before lookup/copy of `out-fln`; triples at +8/+0x20. Final stores write the second triple first, then the first, then tag 12. |
| `send-slack-alert` | 10 | `owned(msg)`; triple at +8 before storing tag 10. |
| `run-non-validator` | 2 | Same output-configuration helper into out+8, then store 2. |
| `approve-non-expiring-agent` | 15 | Store 15; no payload store in this path. |
| `change-validator-profile` | 0 or 1 | Detailed below. |

The run variants call slot `0x5776a80`, whose unique relocation addend is
`0x4579310`. Its full 6,623-byte body belongs to existing PR #1748 and is
deliberately excluded. This packet does not reinterpret its thirteen fields.

## Profile layout: optional commission is the first word

The profile path first copies required `abci-state-fln`. It then processes,
in this order: optional `node-ip`, optional `name`, optional `description`,
`presence(unjailed)`, optional `disable-delegations`, optional `commission-bps`,
optional `signer`. Each present value is converted before the next lookup.
These distinct option literals, their exact pointer/length pairs, branch
instructions and final stores are retained; no defaults from the preceding
CLI builder are inferred.

| Command offset | Stored bytes / condition |
| --- | --- |
| +0 | Full qword 0 if `commission-bps` lookup returned zero; full qword 1 after a successful present conversion. |
| +8 | Converted u64 commission when present; inactive saved R13 value otherwise. |
| +0x10, +0x18, +0x20 | Required `abci-state-fln` owned triple. |
| +0x28, +0x30, +0x38 | Optional `name` triple; first word `0x8000000000000000` when absent. |
| +0x40, +0x48, +0x50 | Optional `description` triple, same absent sentinel. |
| +0x58 | AL from `presence(unjailed)`. |
| +0x59 | Signer presence byte 0 or 1. |
| +0x5a..+0x6d | 20 bytes produced by the signer adapter if present; inactive scratch bytes otherwise. |
| +0x6e | Low byte of returned node-IP value if present, 2 if absent. |
| +0x6f..+0x72 | Bits 8..39 of the present node-IP return, copied as a dword; inactive saved value when absent. |
| +0x73 | Boolean adapter AL when present; 2 when `disable-delegations` is absent. |

The decisive commission sequence is `TEST RAX,RAX; JE 0x4583baa`; present
values call `0x4584200`, save RAX in R13 and set EBP to 1 at `0x4583ba3`.
The absent branch clears EBP. At `0x4583c42`, `MOV [RBX],RBP` writes the first
word, followed by `MOV [RBX+8],R13`. This rules out a fixed command tag for
this path. It resembles a layout niche, but no exact Rust enum or field type
is recovered from that observation alone.

Missing optional fields do not initialize all their payload registers/stack
bytes. Those bytes are still physically copied by later instructions. They
must not be converted into invented zero defaults, serialized output, or an
unconditional initialized Rust value. Successful construction can perform
allocation before a later required value or conversion fails; no atomic
"validate everything, then allocate" ordering is claimed.

## Support adapters and failure boundaries

The 86-byte boolean adapter accepts exactly lowercase `true` and `false`,
returning AL 1 and 0. On the `true` path, `SETE AL` preserves upper RAX bits;
the caller uses only the byte. This is not an all-RAX boolean claim.
The owned-string adapter `0x4583fc0..0x4584030` copies length bytes and returns
the same `(length,pointer,length)` representation, with pointer 1 for empty
values and an allocation-error boundary for high-bit lengths or null allocation.

The two 262-byte amount/commission adapters accept one optional leading `+`
and decimal digits with u64 overflow checks; empty input and lone signs fail.
The short loop has at most 16 digits and cannot overflow u64. The long loop
uses multiplication overflow and addition carry. On multiply overflow the
already-loaded byte still distinguishes a nondigit from an overflowed digit
before constructing the error discriminator. The inline `wei` loops have the
same success arithmetic, but separate Location records. These bodies are
support for ordering and payload width, not a separate arithmetic contribution
or a native execution comparison.

The node-IP adapter calls relocation slot `0x576eb30` (target `0x13da110`)
and rejects AL == 2. The signer/validator parser uses slot `0x576e840` (target
`0x1444a00`); its byte discriminator 1 reaches the error branch, otherwise
20 payload bytes are copied. The precise accepted address grammar and the
meaning of all result tags remain unproved because these transitive bodies
are excluded. Calling the former "node-IP" follows its option use only.

Missing required values call slot `0x576e470`; conversion failures call
`0x576e048` after preparing a diagnostic payload and a relocated Location.
Allocation failure uses `0x576dfb8`. These slots and actual destination FDEs,
all other call and unconditional-jump sites, runtime-indirect unresolved calls, source Location
records, and RIP data references are in `records.json`. Passing an error-call
boundary is not proof of its display text, termination, unwind action, I/O,
or absence of side effects.

## Caller and attribution

The complete 348-byte context `[0x21dfc30,0x21dfd8c)` allocates and copies the
literal `hl-node` from overlapping dwords at `0x6f6141` and `0x6f6144`, then
calls slots `0x5770490`, `0x5773910` and `0x5770510`. Their targets and FDEs
are recorded, but the builder/parser bodies are not included. If the parser
output's first qword is `0x8000000000000001`, this wrapper copies 56 bytes of
error payload, stores first qword 16 and bypasses the chain constructor.
Otherwise it copies 80 bytes of parsed state to a stack snapshot, calls slot
`0x5773918` at `0x21dfd2f`, invokes cleanup, then `memcpy`s **0x98 bytes** into
its output at `0x21dfd4d`. Both outcomes normally return out in RAX.

All RELA sections are examined. Exactly one writer names the chain entry at
slot `0x5773918`, and one names the command entry at `0x5776a78`; the recorded
call sites resolve through those actual records. The 80,300-record scan also
rejects another writer with a different addend to an already-used destination.
This is not a census of every possible runtime-indirect caller.

Embedded panic Locations refer to `node/src/hl_node.rs`, including chain
20:5, 21:12, 25:14, command branches across lines 79..127, and adapters
99:9, 128:9, 136:9, 138:9, 140:9. That supports the private startup ownership
inference. No public upstream source/version identity, source text, original
compiler options, recovered dependency lockfile, whole ELF equivalence or
complete CLI grammar is claimed. Inactive bytes, allocator behavior, hash/
conversion closure and parser defaults make a faithful standalone Rust API
premature; this packet deliberately supplies the static boundary first.
