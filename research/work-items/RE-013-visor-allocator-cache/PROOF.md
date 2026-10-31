# Local fast-return value and address provenance

This is a conditional static proof for captured visor SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
The owned linked-VA range is `[0x70bf30,0x70bff2)`, 194 bytes. No allocator
correctness, initialized cache state, requested storage, alignment, freshness,
lifetime, non-null result or target defect is inferred.

## Domain and symbols

Addresses in evidence are **linked ELF virtual addresses**. The image has
ELF e_type=3; let D denote its unobserved runtime load bias. In a mapped trace,
the two RIP-relative table bases are D+0xa0c4c0 and D+0xa0c700. Mapping/relocation
conditions are external; D is not assumed zero. Let B be the architectural
FS base. The separately loaded word T=`load64(B+0)` is **not** assumed equal B.
No private TLS, cache or allocator ABI is assigned to those values.

Require ordinary execution of the admitted immutable instruction bytes, valid
read/write permissions for each cell actually accessed on a chosen route,
and a valid original hardware return state. Every local store must preserve
the original return slot, live caller frame and any required immutable input/
code region. The helper never adjusts RSP or explicitly writes RBX/RBP/R12–R15,
but its indirect writes could alias caller storage absent these conditions.
No asynchronous interference is modeled; actual concurrency/ownership remains
unknown. These are external proof premises, not runtime checks in the tool.

No pairwise disjointness is assumed among the class-header fields, FS-relative
counter fields and the cache cell. Consequently the proof records memory
events **in instruction order**, and does not equate each final field to an
independent pre-entry value. In particular the final counter ADD reads memory
after preceding stores. Aliases must not be silently excluded by identifying
T with B.

Let r be entry RDI, an unsigned 64-bit word. For the small-request route define:

| Symbol | Actual observation / expression |
| --- | --- |
| i | `(r+7)>>3`, only after r<=4096; i is 0..512 |
| c | `load8(D+0xa0c4c0+i)`; zero-extended byte, 0..255 |
| s | `load64(D+0xa0c700+8*c)`; actual initialized value unknown |
| u | `load64(B-0x948)` |
| L | `load64(B-0x940)` |
| q | `(u+s) modulo 2^64` |
| H | `(T+24*c-0xc80) modulo 2^64` |
| p | `load64(H+0x360)`, a cursor word |
| v | `load64(p)`, distinct from p; read before cursor comparisons |
| b0 | `load16(H+0x370)` |
| b1 | `load16(H+0x374)`, only if the first comparison is equal |

These names describe numeric relationships, not original private field names,
units, allocation policy, valid objects or initialized state invariants.

## P1 — complete admitted local graph

The producer authenticates one full immutable input byte vector. GNU receives
only an owned 194-byte, mode-0400 non-executable file in a mode-0700 directory.
Rows must bind those same bytes and tile the exact extent. All nine byte-block
bindings, including two padding NOP rows, are checked. Relative branch targets
are recomputed from encodings and must be instruction boundaries or the one
open slow target. The graph contains 37 rows, six branches and one local RET.
Thirty-five rows are reached from this entry under the unrestricted local
projection; the two padding rows are excluded. These are graph counts, not
reconstructed-function or completion denominators.

The complete acyclic entry projection has five terminal paths: two reach the
local RET at `0x70bfbe`, and three transfer through the common tail jump at
`0x70bfc0` to `0x70a170`. The slow body is not part of the local proof.
There is no local CALL instruction and no assumption about what the tail
callee returns or whether it terminates.

## P2 — request and table guards

`CMP RDI,4096 / JA` at `0x70bf34/3b` transfers larger unsigned requests to
the common slow jump before any table or FS read. For 0<=r<=4096,
`LEA RAX,[RDI+7] / SHR RAX,3` at `0x70bf48/53` is nonwrapping and yields
`ceil(r/8)` in 0..512, including zero. This proves an **address-index bound**,
not an allocation-size bound.

The byte map at linked 0xa0c4c0 therefore needs a 513-byte envelope; the qword
table at linked 0xa0c700 needs a conservative 2048-byte envelope for all byte
values c. Both envelopes lie in SHT_NOBITS `.bss`. Their section coordinates
are observed, but there are no initialized table bytes in the capture. The
tool refuses to read NOBITS as if it were file-backed data. Loader-zero state
must not be substituted for actual post-initialization allocator contents.

`MOV RCX,-0xc80` plus FS displacements +0x338/+0x340 gives the separate
counter/limit addresses B-0x948 and B-0x940. The ADD forms q with 64-bit wrap;
the subsequent unsigned `CMP/JAE` at `0x70bf6f/77` transfers q>=L to the slow
target. It does not establish that the addition did not wrap, that s>=r, or
that either quantity has a particular allocator accounting meaning.

## P3 — cursor addressing and read order

On q<L, `MOV R11,fs:0` at `0x70bf79` reads T, not architectural B itself.
Two LEAs and ADD RCX form H=T+24*c-0xc80 modulo 2^64. The helper loads p at
`0x70bf8d`, then **v=load64(p)** at `0x70bf94`, and only afterward compares
low16(p) with b0 at `0x70bf9b`.

Thus even a route eventually taking the cursor slow fallback has already
read p's cell. The comparisons do not test v, and do not establish that p's
cell or the returned word is a valid allocation. Their readability is a
premise; no local bounds-before-read or safe-dereference theorem is claimed.

## P4 — two accepted cursor paths

If low16(p)!=b0, the path at `0x70bfa4` performs:

1. `store64(H+0x360,(p+8) modulo 2^64)`;
2. `store64(B-0x948,q)`;
3. at `0x70bfb3`, read the **current** word at H+0x368, add one modulo 2^64
   and write that result back.

If low16(p)==b0, the helper reads b1 and compares it with low16(p) at
`0x70bfc8`. Equality goes to the common slow target. Inequality at this second
test selects `0x70bfd1`, which performs:

1. `store64(H+0x360,(p+8) modulo 2^64)`;
2. `store16(H+0x370,low16(p+8))`;
3. `store64(B-0x948,q)`;
4. at `0x70bfe8`, read the **current** word at H+0x368, add one modulo 2^64
   and write it back.

These are ordered event relationships. For example, with a symbolic class c,
choose T=B-0x30-24*c. Then H+0x368=B-0x948: the counter ADD reads the value
just stored by the preceding FS-relative total store, rather than an
independent entry counter. This is address algebra showing why a stronger
final-state assertion would need more separation; it is not execution or
evidence of a real allocator defect/state.

## P5 — returned word on every local return

Both accepted paths merge at `0x70bfbb`, `MOV RAX,RSI`, then local RET.
The last definition of RSI is `MOV RSI,[RDX]` at `0x70bf94`, which loaded v.
No instruction on either path subsequently changes RSI. Every local return
is dominated by that load and the final register move. Therefore RAX=v,
the **pre-update loaded word**, even if a later data store changes p's cell.
The valid-return/code/frame premises above remain necessary.

No branch checks v for null or alignment. The actual comparisons concern
RDI, R10 and DX. Absent external live-cache invariants, the local def-use
relation allows v=0 or an unaligned word such as 3 under otherwise admitted
symbolic readable/cache-write conditions. This is a missing-premise argument,
not a claim that the running allocator produces such values. Requested
capacity, pointer validity, freshness and lifetime remain unknown.

## P6 — open tail paths and caller linkage

The three transfer predicates are r>4096; r<=4096 with q>=L; or r<=4096 with
q<L and low16(p)==b0==b1. All reach the same `JMP 0x70a170`. RDI is only
read by the local body and is never written, so the original request word is
forwarded unchanged. The slow target has a separate 7,611-byte FDE; only its
metadata and hash are retained. It has not been decoded, and its return,
allocation-size/alignment/null and failure contracts are open.

The used RELATIVE relocation at linked slot 0x7e4b60 targets this helper.
Three already observed collection windows, 12+13+9=34 bytes, bind the actual
RDI setup for first positive payload length, initial record-storage request
and later positive payload length. These are **revisited prerequisite bytes**,
not new native coverage or a re-proof of the collector's interval/capacity
results. Actual runtime relocation and allocator invocation remain external
load/call conditions.

## Limits

This finite local value/address proof explains which unobserved table/cache
invariants the collection's external allocator contract still needs. It
does not replace those premises with an invented allocator model. It does
not qualify the slow body, global TLS ABI, concurrency, caller lifecycle,
error/unwind, memory allocation correctness, private Rust/C++ types or any
component/build/equivalence gate. No captured code or emulator is executed.
