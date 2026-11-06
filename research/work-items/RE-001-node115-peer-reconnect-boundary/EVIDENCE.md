# RE-001 / peer-protocol: node115 reconnect-diagnostic local boundary

- Component: peer-protocol; bounded static coordinate finding, not an implementation.
- Target: node115 Linux x86-64, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Status: native byte/relocation/FDE observations; source association inferred from Location-shaped metadata. No runtime reachability or behavior proof.

## Question and result

Locate one first-party reconnect-error diagnostic outside the known outbound
worker `[0x5a7f6f0,0x5a8024b)` and bind it to source-use metadata and local stores.
Native range `[0x5a82670,0x5a89535)` contains the diagnostic-associated excerpt
`[0x5a87930,0x5a87a52)` (290 bytes). GNU readelf -wf supplies its unique FDE.
The excerpt is original target disassembly, not source code or executable fixture.

At `0x5a87930`, RIP-relative LEA selects `0x445ff6`. The next 83 bytes beginning
`0x445ff7` read `forward_client_blocks process_client_block_wire error, reconnecting to a new peer: `.
The preceding byte is raw 83; no complete string-encoding format is recovered.
At `0x5a879cb`, LEA passes `0x64b9228` in RCX before an indirect call.
An R_X86_64_RELATIVE relocation at that slot points to `node/src/nv_stream.rs`;
the following length/u32/u32 are 21/254/37. This supports a source-use association
with `node/src/nv_stream.rs:254:37`, not ownership or the original function name.
The call at `0x5a879e2` uses slot `0x64e0b18` with its independently checked
relative addend; the next direct call is `0x5a4b050`. Helpers are not analyzed.

On normal helper return the excerpt zeroes word owner+0x1a6 and byte+0x1a8,
loads an object from owner+0x120, and attempts a byte CMPXCHG at object+0x10.
The non-contention arm stores object+0x68=2 before a second CMPXCHG. Its
non-contention continuation stores raw binary64 bits `0x3fb999999999999a` to
owner+0x1b0, clears byte owner+0x240, then jumps `0x5a8506f`. JNE targets
`0x5a88a6d` and `0x5a88a80` are recorded but not analyzed. There is no claim
that the whole route holds a lock, that helpers return, or that these fields
have a recovered type, timing unit, peer identity or delivery guarantee.

## Reproduce

From repository root, with authenticated LFS target present:

```sh
python3 research/work-items/RE-001-node115-peer-reconnect-boundary/verify.py
python3 -m unittest discover -s tests -p test_node115_peer_reconnect_boundary.py -v
objdump -d -M intel --start-address=0x5a87930 --stop-address=0x5a87a52 artifacts/node/115/hl-node
readelf -wf artifacts/node/115/hl-node
```

`verified.json` records exact target/excerpt identities, file offset and observed
GNU readelf version. The retained excerpt was decoded with GNU objdump 2.40.
The independently authored verifier uses only Python stdlib and native readelf;
it parses ELF load mappings and RELA entries without repository helper imports.
It checks instruction operands, actual data, source Location fields, both call
identities, local stores and all three outgoing edges. It is not an emulator or
a semantic comparator. Exact-byte obligations bind observations to this target;
no normalization or cross-version equivalence is proposed.

Scoped tests require the real authenticated target (no skip/mock fallback).
Controls mutate real instruction displacement, diagnostic bytes, Location xref,
line metadata, store value, raw float immediate, continuation edge and relocation
types. Low-level mutation checks deliberately bypass whole-file hash rejection so
specific evidence checks must detect the corruption; a separate digest control
checks production identity rejection. Full native CLI replay checks actual FDE.
No mutated target is executed or written. Test outcomes are recorded below only
after execution. Independent required checks remain pending until controller
validation returns; this file is not a full-suite PASS receipt.

## Overlap and useful limit

The FDE is already known to integrated input/limit/block-fill-writer, LU-grant,
bootstrap and gossip packets. This does not rediscover it. A focused integrated
work-item scan found no existing claim at this diagnostic/Location/store route;
the outbound-age-gates packet covers a disjoint FDE. Literal public reconnect
searches found no open work but do not prove semantic absence. Complete live
overlap is rechecked by the contribution controller before publication.

No Rust implementation, whole-function CFG, incoming error branch, contention
helper, jump continuation, source ownership, original build or full-node
equivalence is established. No target process, live chain, network, signing,
keys or paid data were used. No progress/catalogue gate changes. Newly authored
verifier/tests are project code; imported binary/disassembly retains upstream
rights. Next question: follow the existing reset continuation and incoming
carrier only after new scope/overlap checks; neither is claimed here.

## Observed local proof

Execution `437b6326add8d4bbf01c7a22dca3ef24`: target verifier and initial
four scoped tests passed, command wall4.217s. Execution
`9c0ae37fa7fa4f3c0332db33073318aa`: all five scoped tests including native
FDE replay passed (unittest4.096s, command4.317s). Eight real instruction/data
mutations, two relocation-type mutations and one identity mutation were
rejected. Native FDE replay is an unmutated external-tool check, not a
corruption control on unwind metadata. Excerpt file offset `0x5a86930`;
SHA-256 `c5e53989de7e3487a95e7458d42a86e74bd26ae22fcb01b9aeada610b5e3efb1`.
These are local observations only; required independent validation is pending.
