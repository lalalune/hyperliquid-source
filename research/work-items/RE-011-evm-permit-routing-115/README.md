# RE-011: trace node 115 EVM RPC permit routing and outcomes

Node #115 encodes a shared two-selector expensive-call permit protocol: the
registration-linked `eth_call` and `eth_estimateGas` paths initialise selector
0, a filter-shaped RPC path initialises selector 1, and the post-merge routing
map pointer is carried into the request lookup through selected closure and
future objects, and one merge rejects duplicate names before writing;
reconstruction must preserve the distinct acquisition results.

- Component ID: `evm-rpc`; task `RE-011`, with bounded `evm` dependency and
  historical fork context.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: hyperliquid-source
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; the pinned public
  `hyper-evm-sync` reference is `d0945c699d9d4774417f4355b10744e7cd420df8`.
  The unlicensed inferred reference revision
  `999556f6e0a474b8312db96ec3149e1c44e97c23` was a lead only; no code was
  copied and it is not an input to the generator.
- Claim status: the byte-level facts below are observations; method transport,
  timer meaning, source-level names, and runtime reachability are explicitly
  conditional inferences.
- Scope included and excluded: selected route registration, conditional
  method lookup and callback, permit configuration, asynchronous acquisition,
  timer and cleanup branches. Full HTTP parsing, wire error codes, all EVM
  operations, EVM state transitions, fork patches, chain data, and whole-node
  equivalence are outside this packet. This is static analysis; no captured
  node or visor, network, keys, or chain actions are used.

## Reproduce

Run from the repository root on Linux x86-64 with the authenticated #115 input
materialised. The collector uses Python 3 standard library and the repository
`tools/elf_index.py` and `tools/fde_extents.py`; it does not run a disassembler
or any other program. The run used Python 3.12.3. It authenticates the complete
input SHA-256 before parsing or creating output. The generated files contain
only linked virtual addresses, file offsets, bytes, hashes, and selected
relative diagnostic suffixes; build-machine path prefixes are omitted.

```sh
python3 tools/evm_permit_routing115.py --out research/work-items/RE-011-evm-permit-routing-115
python3 -m unittest tests.test_evm_permit_routing115 -v
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For a reproducibility check, create a writable temporary directory, substitute
its name for `<tmp-dir>`, then run:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/evm_permit_routing115.py --out <tmp-dir>/first
PYTHONHASHSEED=37 TZ=Pacific/Honolulu python3 tools/evm_permit_routing115.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
```

Compare each of `evidence.json`, `branches.tsv`, `calls.tsv`, `methods.tsv`,
and `states.tsv` with its corresponding file in this packet.
The generator writes these five files only; it does not write this README or
`MANIFEST.sha256`. From this packet directory, `sha256sum -c MANIFEST.sha256`
checks all packet files except the manifest itself.

As an independent human instruction-boundary check, GNU objdump 2.42 was run
from each selected FDE start, for example:

```sh
objdump -d -w -M intel --start-address=0x2e38640 --stop-address=0x2e3941e artifacts/node/115/hl-node
objdump -d -w -M intel --start-address=0x2a04070 --stop-address=0x2a0465c artifacts/node/115/hl-node
objdump -d -w -M intel --start-address=0x2b69af0 --stop-address=0x2b69d19 artifacts/node/115/hl-node
```

The last stop is the decoded FDE end, not the next unwind-index start. Neither
objdump output nor its formatting is an input to the collector or tests.
`evidence.json` preserves the complete selected FDE body hashes, CIE/FDE and
unwind-index record bytes, and frozen instruction windows; it does not claim
that all instructions or CFG paths were semantically decoded. File offsets are
zero based; virtual addresses are linked ELF VAs, before load relocation.
Every stated FDE end is exclusive.

## Evidence

### Registration and request lookup

The same initialisation range `0x2e375a0` calls the limiter constructor through
RELATIVE slot `0x64e22a8` at `0x2e37647` and the method-table builder
`0x2a05f60` at `0x2e377b8`. The builder returns three words; the caller copies
two words into a later allocation. The selected post-merge pointer transport
into the request lookup is traced below, under explicit dynamic-call conditions.

| Method literal | Registration call / FDE | Descriptor table | Tag-one callback slot / target | Returned future poll | Inner poll | Initial selector |
| --- | --- | --- | --- | --- | --- | --- |
| `eth_call` | `0x2a05fbf` / `0x2d02f60` | `0x6450998` | `0x64509c0` / `0x2d03200` | `0x2d087e0` | `0x2a2a0e0` | 0 |
| `eth_estimateGas` | `0x2a0602b` / `0x2d02a20` | `0x6450878` | `0x64508a0` / `0x2d03ba0` | `0x2d062f0` | `0x2a225c0` | 0 |

`methods.tsv` derives each literal pointer and length from the LEA and length
instruction, and the callback and poll targets from the table-slot RELATIVE
relocations. Both registration functions store descriptor tag 1 and call the
same insertion routine through slot `0x64e2198`. Its helper `0x2f1b5f0`, on
the selected new-entry arm, returns the input key pointer and length. The
stores in `0x2f1bce0` then lay out five qwords at A: key pointer, key length,
tag, descriptor pointer, and descriptor table. For the selected bucket index
`i` and control-array base `D`, A is `D - 40*(i+1)`.

The request-associated range `0x2e3cb60` calls `0x2e38640` at `0x2e3d46e`
and `0x2e3e745`. In `0x2e38640`, the candidate length comparison at `0x2e38c5a`
precedes the call at `0x2e38c8a` through a slot whose dynamic symbol record
names `bcmp`; zero selects `0x2e38f6c`. Relative to E = `D - 40*i`, the
subsequent descriptor words are at E-24, E-16, and E-8. Tag 1 takes
`0x2e3904c` and eventually calls table offset `0x28` at `0x2e3913b`. On the
empty-map or empty-control-byte branch the range constructs a payload using
the literal `Method not found` at `0x453cf0`. This establishes a selected
lookup and a missing-candidate path; it does not establish an HTTP or JSON-RPC
error code.

For `eth_call`, the callback at `0x2d03200` constructs an allocation and
returns the table at `0x6450a28`; its slot at offset `0x18` has addend
`0x2d087e0`. That poll range constructs an inner object, uses table
`0x6445868`, and calls its offset `0x18` at `0x2d090c3`; the slot's relocation
addend is `0x2a2a0e0`. The gas route has the corresponding chain in
`methods.tsv`. An allocation failure and a nonpositive signed result of a
reference-count increment have separate trap-oriented branches. These
relationships require normal relocation and preserved values.

### Conditional map transport into lookup

The first observed merge checks each key of its second map against the builder's
map. The membership helper `0x2f1b8e0` compares candidate lengths and calls the
`bcmp` slot: a match returns 1, while an empty map or an exhausted search
returns 0. Wrapper `0x2f1bf50` returns tag 3 for an absent name and tag 0 with
the name for a present one. The loop at `0x2e37920` continues on tag 3; tag 0
reaches `0x2e38289`, whose diagnostic says a `Result` unwrap received an
`Err`. Thus a duplicate name is rejected on this selected preflight. A later
writer `0x2a32130` has both an absent-key insertion arm and an equal-key arm
that replaces the descriptor's three words. The latter is a real code path,
but this packet does not claim it executes when the successful preflight and
map contents stay consistent. This analysis does not cover every later merge.

The remaining trace follows the final map pointer after router merging; it
does not assume that the pointer retained its initial allocation or that all
prior entries survived every later operation. `0x2f1bb50`, called through slot
`0x64e88b8`, may reuse the existing pointer or allocate and store a replacement
before returning the map interior. The builder registers through that helper,
and the initialiser calls it again at `0x2e3793a` during its merge. These
branches prevent assuming the original pointer identity.

| Selected step | Pointer transfer or target derived from #115 bytes |
| --- | --- |
| Box router state | Final stack word at `+0x70` passes through stack `+0x10` into box `+0x10`; the `0x28`-byte box also stores constructor `0x2dd6ae0` at `+0x20` and is tagged 2 with table `0x6450488`. |
| Install and clone | The tag-2 arm at `0x2d4adf0` invokes table offset `0x18`; RELATIVE slot `0x64504a0` points to `0x2cfe810`. This calls `0x2e067c0`, whose normal return preserves the word at input `+0x10` at output `+0x10` and increments its referenced count. |
| Construct state | Box table slot `0x64504a8` points to `0x2cfe4c0`. On its selected factory call, the function at box `+0x20` copies the first `0x20` bytes into a new allocation and returns state table `0x6451368`; its slot `0x6451388` points to `0x2e4c690`. |
| Alternate wrapper | Box slot `0x64504b0` points to `0x2cfe6a0`, which calls the same stored factory and calls state table `+0x28`; slot `0x6451390` points to `0x2e332e0`, which again clones the selected state. |
| Make request future | `0x2e4c690` calls the same clone helper, copies the resulting word from its stack `+0x140` into a future whose source begins at stack `+0x20`, so the word lands at future `+0x120`. Its table `0x6452f78` has poll relocation `0x6452f90` to `0x2e3cb60`. |
| Supply lookup | In `0x2e3cb60`, the word at `+0x120` is copied to `+0x318`. The single-request arm puts a pointer to `+0x318` into its lookup future at `+0xe8`; `0x2e38640` dereferences that pointer before reading map metadata. |

`evidence.json` reports the offsets decoded from each displacement, the
closure-slot relocation bytes and targets, and frozen instruction windows.
The transport collector rejects inconsistent offsets or a relocation that
points outside the FDE containing the expected instruction witness. A normal
allocation and a positive signed count are required at the clone sites; the
allocation-failure and nonpositive-count paths reach trap-oriented handling.
The packet does not establish which generic server dispatch chooses each
indirect slot, or prove that all later merges and opaque operations preserve
both entries in all conditions.

### Selector, replacement, and handoff

The two method-associated inner ranges initialise the future byte at offset
`0x1f3` to zero and call `0x2a04070`; `0x2a2cb70` instead writes one before
calling it. This third range has an EVM RPC store Location and, before the
permit path, makes five unsigned comparisons against 1000. Each of the first
four values greater than 1000 goes to the same failure corridor; the fifth
value at most 1000 takes its continuation. The failure corridor references a
format string about addresses or topics. The exact field-to-source-type map
and public method binding are unresolved.

On the initial state of `0x2a04070`, the selector travels through
`0x29cc120` to `0x2a353d0`, whose atomic byte lock encloses the call through
slot `0x64e22b0` to `0x175d250`. If the refresh helper at `0x16e5ba0` returns
zero, that range skips replacement. Otherwise it compares two configured
counts, each clipped to `0x1fffffffffffffff`, against the previously stored
count for its corresponding slot. For a changed count it requests a `0x38`-byte object,
sets two initial qwords to one, writes twice the clipped count at object
`+0x30`, drops a reference to the old pointer, and stores the new pointer and
clipped count. Equal counts bypass the respective replacement. Allocation
failure calls the failure slot before `ud2`; a selected reference increment
with a nonpositive signed result also reaches `ud2`.

Selector 0 reads a pointer from object `+0x68` and a binary64 value from
`+0x20`; selector 1 uses `+0x78` and `+0x30`. The pointer is returned in RAX
and the value in XMM0. The caller saves the value, calls the converter at
`0x15ed960`, and constructs a timed future with `0x2b13e50`. The exact
floating-point conversion for all negative, nonfinite, and boundary inputs has
not been recovered. This packet does not assert configuration defaults, names,
or full consistency under concurrent configuration changes.

On tag `0x28`, `0x2a2a0e0` copies the returned fields into a following object
and calls `0x2e4ac30`, which itself performs an indirect poll. Its ultimate
callee and the subsequent EVM execution are not established here.

### Poll results and cleanup

| Captured inner condition | `0x2b69af0` result word | `0x2a04070` output byte | Caller continuation |
| --- | --- | --- | --- |
| Acquire poll returns 0 | 0, with nonzero pointer on the observed normal arm | `0x28` | copy permit fields and poll the following object |
| Acquire poll returns 1 | 0, with null pointer | `0x26` | take the non-`0x28` arm |
| Acquire poll returns 2; timer poll returns zero | 1 | `0x26` | take the non-`0x28` arm |
| Acquire poll returns 2; timer poll returns nonzero | 2 | `0x29` | propagate pending and save resumption state |

The byte-level distinctions are observations. Interpreting the first two arms
as acquired versus closed and the third as timeout is an inference supported
by the queue-counter operations, timer polling chain, and timer diagnostic,
not a runtime test. Payload bytes outside the tag on the timer-ready arm are
not qualified. No numeric JSON-RPC error is inferred from `0x26`.

`states.tsv` decodes four signed relative entries for each of three nested
permit tables and the inner acquisition table. In the outer table, state 0
enters initialisation, state 3 resumes, and states 1 and 2 lead to separate
terminal helper calls. The code writes 3 on pending, 1 after a completed
result, and 2 in unwind handling. The selected entries are not a statement
about out-of-range discriminants. `0x2b69af0` calls the acquisition poll
`0x5ce6940`; the timed branch goes through `0x5ce94c0` to `0x5cf2d30`, where a
sentinel check reaches a timer-disabled diagnostic. Both ordinary completion
and the outer cleanup chain reach `0x5ce6750`. When its queue-state byte is
1, that helper takes an atomic lock and rewires waiter links before its
count-related continuation. Exact wake order and all unwinding races remain
unresolved.

### Dependency and fork context

The historical `RE-011-evm-rpc-method-path` packet, at source commit
`275e53b0`, studied node #94 (SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`)
and included a separate fork-path comparison for node #115 with the target
digest stated above. Its already-recorded path inventory was reviewed for
context and is not regenerated as new evidence here. No #94 coordinates or
inferred implementation are reused. The pinned public sync repository is a
separate artifact; its revision does not establish the node's dependency
versions, exact upstream revisions, or private fork patches.

### Inferences and conditions

The registration-to-callback connection assumes successful new-entry storage,
preservation of the inserted key and descriptor through the later map merge,
the selected dynamic closure invocations, a lookup that reaches the
corresponding bucket, ordinary PIE relocation, and normal dynamic `bcmp`
binding. The selected post-merge map-pointer transport is byte-backed above;
full pointer ownership across opaque helper calls and arbitrary concurrent
mutation are not proved. The
FDEs and diagnostic Locations support attribution of ranges, not original
source-function boundaries. `eth_call` and `eth_estimateGas` are exact embedded
literals, while the third selector-1 path remains filter-shaped rather than a
verified method registration. The recorded permit-state observations do not
validate downstream EVM execution or public request reachability.

## Implementation and comparison

not yet implemented. No Rust component, Cargo graph, compiler flags, two-build
comparison, target execution, normalization mask, helper closure, vtable/data
closure, relocation closure, or complete EVM behavior comparison is claimed.
The test controls exercise digest admission, frozen-byte corruption, truncated
and changed instructions, jump targets outside their FDE, duplicate or wrong
relocations, missing files, and NOBITS/ambiguous section mappings. They test
static evidence collection, not on-chain behavior.

## Results and limitations

The bounded packet contains 42 indexed FDE ranges, 122 frozen instruction
windows, 37 selected direct or relocated calls, 52 conditional branches, 16
state-table entries, 23 selected relocations, nine Location-shaped records,
and two method associations. These are selected evidence counts, not a
function, method, or whole-ELF coverage denominator. No component gate is
advanced; both `evm` and `evm-rpc` remain at their existing 0/4 status.

Next question: prove entry survival across later map merges and the generic
server dispatch, then preserve the selector-0 permit across the indirect
post-acquisition poll, including release and wire-error mapping, against #115
bytes.
