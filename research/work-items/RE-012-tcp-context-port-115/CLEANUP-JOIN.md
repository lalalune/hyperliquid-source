# RE-012: accepted-state cleanup preserves the selected copied word

- Component `transport`, task RE-012; only this evidence packet is modified.
- Sole target Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `05bc2de303c05525b71e7e257426e741bc66a390`.
- Status: binary-backed selected-path join, with explicit ABI/storage premises.
- Question: does cleanup `0x2a9dcd0`, called at `0x2ad5e3e`, overwrite the
  accepted-context word between the two copies in [FACTORY-JOIN.md](FACTORY-JOIN.md)?

On the previously selected acceptor return, the state byte read by cleanup is
**1**. The cleanup's corresponding path has **13 instructions**, no nested
call, no dynamic tail transfer and no explicit memory destination. Its only
writes are the three register-save pushes on its own stack. Together with
the caller's return-address push, these miss the pending context word.
This narrows one named helper premise in the listener-to-factory chain.
It does not establish other cleanup states, scheduler dispatch or resource lifetime.

## Target evidence and bounded ownership

All addresses are linked ELF VAs before load bias. Actual FDE records, body
hashes, file offsets, LSDA references, native exports, edge lists and control
results are retained in [cleanup/records.json](cleanup/records.json).
[cleanup-spec.json](cleanup-spec.json) pins the instruction spans and relocations.

| Interval | Bytes | Role |
| --- | ---: | --- |
| `0x2a9dcd0..0x2a9de09` | 313 | Cleanup body, including other states and unwind tails |
| `0x2afae20..0x2afbc22` | 3,586 | Previously recorded acceptor context |
| `0x2ad5980..0x2ad655e` | 3,038 | Previously recorded outer caller context |

The three complete FDE intervals contain **6,937 bytes / 1,376 Capstone
instructions**; cleanup alone contains 77 instructions. These are capture
denominators, not recovered-source coverage. No implementation comparison or
new full-scope gate is added. Both native exports of each old context body
match the retained factory exports byte for byte. The selected caller and
callee are bound by the encoded direct call, not by nearby labels or seeds.
The current #115 seed catalogue has no inferred address seeds.

## State production and the intervening copy

Use `R` for the outer routine's retained state pointer, `AP=R+0x198` for
its acceptor state, `OS` for outer post-prologue RSP and `AS` for the
acceptor's separate post-prologue RSP. These are manual coordinate names,
not recovered Rust types.

1. Outer `0x2ad5de6` puts `R+0x198` in R15. At `0x2ad5df5` it passes that
   value in RSI to acceptor `0x2afae20`; the latter retains RSI in RBX at
   `0x2afae39`. Its return-output pointer is `OS+0x370`.
2. On the existing selected branch, `0x2afb744` does not take the R12==2
   branch. The `memcpy` at `0x2afb75b` copies `0xb8` bytes from `AP+8` to
   the return output. The tracked field becomes `OS+0x400`.
3. After that call, `0x2afb761` sets AL=1 and jumps directly to `0x2afb8a8`,
   which writes **BYTE `[AP+0xc9]=1`**. The remaining instructions restore
   the stack/registers and return; there is no intervening call after this
   state-byte write. AP+0xc9 is outer state `R+0x261`.
4. Outer `0x2ad5e02` tests a separate **DWORD result tag at `OS+0x370`**.
   The selected not-equal-to-2 branch copies `0x98` bytes at `0x2ad5e25`:
   `OS+[0x370,0x408)` to `OS+[0x2d8,0x370)`. The tracked word becomes
   `OS+[0x368,0x36a)`.
5. Two loads retain separate returned address values. At `0x2ad5e3b`,
   RDI=R15=AP; the following direct call invokes `0x2a9dcd0`.

The DWORD result tag and BYTE acceptor state tag are different locations and
must not be merged into one inferred enum. The post-return path has one
intervening imported operation, `memcpy`, before cleanup. The tag-1 join
therefore requires ordinary `memcpy` behavior, SysV callee-saved RBX/R15,
separate state/stack storage and no concurrent/asynchronous tag mutation.
In particular, the copy destination must not overlap `[AP+0xc9,AP+0xca)`.
The instructions alone do not prove allocator ownership or that disjointness.

## What the selected cleanup actually does

At `0x2a9dcd7`, cleanup zero-extends BYTE `[RDI+0xc9]` into EAX. It compares
against 3, taking the equal branch only at `0x2a9dce1`; otherwise it compares
against 4 and takes the **not-equal** branch at `0x2a9dce6` to `0x2a9dd7e`.
For the joined value 1, this reaches the epilogue and RET at `0x2a9dd85`.

The entry pushes R14, RBX and RAX. At this call site cleanup entry RSP is
`OS-8`, so the three eight-byte stores occupy `[OS-32,OS-8)`. The caller's
return-address push occupies `[OS-8,OS)`. All four miss the pending word
`[OS+0x368,OS+0x36a)` on a valid nonwrapping stack. Pops, the stack adjustment
and RET do not write that word. No object pointer is passed to another
function on this path because there is no nested call or tail call.

After normal return, `0x2ad5e58` copies the pending `0x98` bytes to `OS+0xf8`,
putting the word at `OS+[0x188,OS+0x18a)`. This is the next established edge
of the factory packet. The cleanup itself no longer needs an opaque
destructor side-effect premise on this selected tag-1 path.

The same first two comparisons take this immediate-return path for 254 byte
values (everything except 3 and 4). This finite comparison partition does
**not** establish that those values are valid reachable states. Only value 1
is joined to the selected acceptor return here.

## Excluded paths and preserved gaps

The full cleanup body contains two explicit atomic decrement instructions,
`0x2a9dd19` and `0x2a9dd89`, on alternate state-4 subpaths. Their destinations
come through QWORD `[AP+0xf8]`, rather than being fixed fields of AP. The
body also has conditional helper calls and object-derived indirect transfers.
State 3 can call through slot `0x64e71e0` and tail-transfer through an
object-derived slot `+0x18`; state 4 can reach `0x2abc7e0` and ultimately
tail-transfer through a pointer loaded from `[AP+0xd0]`. The immediate-return
claim must not be generalized to these states or to exception paths.

All cleanup calls/jumps, their encoded bytes and selected RIP-slot relocations
are retained in the records. Imported/helper behavior, dynamic callback
identity and unwind effects are not newly analyzed. A focused direct-call
query also found another outer call at `0x2ad6419`; it is outside the selected
join. No complete caller inventory or general destructor implementation is claimed.

The remaining chain still requires valid copies, nonaliasing storage,
compatible runtime/ABI behavior and no interfering writes. Constructor
contention, TLS fallback contracts, scheduler invocation identity, large-A
helper mutations and the initial origin of large B remain separate gaps.

## Reproduce and verification

With Python 3.12, Capstone 5.0.7, GNU objdump and llvm-objdump on PATH, run
from the repository root into fresh directories:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/cleanup.py --out work/context-cleanup-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/cleanup.py --out work/context-cleanup-optimized
```

The collector authenticates the complete target before interpreting data.
Native commands and exact versions are in [cleanup/commands.json](cleanup/commands.json)
and [cleanup/versions.json](cleanup/versions.json). Both decoders retain every
byte and agree with Capstone partitions with documented standalone LOCK-prefix
joins. No bytes are masked. Decoder agreement is not a full CFG or behavior proof.

The **40 corruption/scope controls** reject 11 changed anchor bytes, ten
changed/duplicate relocations, three truncated FDEs, two store-inventory
changes, two forced excluded branches, four out-of-scope tags, four invalid
intervals, two wrong captures and two truncated native exports. Full-body
hashes can reject changed bytes before specific anchor checks. Edge selection,
tag partition and interval checks are static/scalar annotations, not execution
or emulation of the captured node. Adjacent interval boundaries are also checked.

Normal and optimized collection outputs are identical. The full existing
factory collector was replayed and compared with its retained outputs.
Exact check results, raw-log hashes, the corrected test-discovery attempt and
existing repository limitations are in [cleanup-validation.json](cleanup-validation.json).
Catalogue checking still reports stale generated README content; the earlier
incomplete full suite in [validation.json](validation.json) remains incomplete.
The earlier TLS metadata-path failure is not reclassified as passing.

There is no independent-agent review, captured execution, Rust implementation,
hosted CI, container result or whole-node equivalence claim. No commit, push,
external message, socket, key or chain action occurred. All 92 gates remain false.

Next: classify the outer operations after `0x2ad5e58` and before the executor
handoff at `0x2ad6325` / `0x2ad633a`, focusing on writes that could reach the
copied word and calls that still require preservation premises. This extends
the same selected route without assuming the whole outer state machine is known.
The subsequent [outer handoff census](HANDOFF-WRITES.md) now records those
selected writes/copies and exposes a nested scratch-write boundary; it retains
alias, helper, initialization and scheduler limitations.

New analysis and collector code are independently authored MIT work. Captured
bytes and referenced evidence retain their original rights.
