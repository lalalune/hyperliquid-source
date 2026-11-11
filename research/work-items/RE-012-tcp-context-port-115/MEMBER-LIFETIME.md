# RE-012: the large callers' context member and its selected copy lifetime

- Component/task: transport / RE-012, with RE-001 address bindings.
- Sole target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Scope: the member passed as context by FDEs A `0x2accee0..0x2ad0db0`
  and B `0x2ad0db0..0x2ad4db7`; complete cleanup-helper interval
  `0x2ab9750..0x2ab9808`. Addresses are linked ELF VAs before load bias.
- Owned changes: this evidence packet only. No imported evidence, shared tool,
  implementation, catalogue or acceptance gate is changed.

## Result

There is a selected 24-copy relation in **each** large caller from its input
WORD at `parent+0x90` to `parent+0x11a8`. The latter is exactly the low word at
offset `+0x90` of the context passed at `parent+0x1118` in [ROUTE-MAP](ROUTE-MAP.md).
The member therefore has an input-field provenance on these selected paths,
rather than an independently observed port constant in the large caller.

This is a **conditional static copy relation**: it assumes the selected
initial/success paths, normal copy behavior and no intervening alias/helper
mutation of the tracked bytes. The last assumption is not yet proved for all
callees or resumes. It must not be reported as an immutable-field proof or as
an end-to-end constructor-to-send behavior test. In particular, this packet
does not assign 3999, 4002 or another constant to either large caller's input.

The field's live location moves through larger, reused storage. At initialization,
the large `0xf00` copies start at parent `+0x1128`; later `0x1eb0` and `0xf80`
copies start at `+0x10a8`. Those ranges overlap the eventual context member.
A struct declaration treating `parent+0x1118` as one stable live object in all
states would erase an observed phase distinction.

## Evidence and copy coordinates

`P` below is the unchanged RBX input base of the respective caller. `S` is its
post-prologue RSP, which is a different coordinate system in each function.
All copy edges, selected call/load instructions and their byte anchors are in
[members-spec.json](members-spec.json); every intermediate position of the
tracked two bytes is in [members/records.json](members/records.json).

| Stage | A: original evidence and positions | B: original evidence and positions |
| --- | --- | --- |
| Entry copies | `0x2accfa6`, `0x2acd04e`: P `+0x90 -> +0x1f8 -> +0x2b0` via two `0x98` copies. | `0x2ad0e73`, `0x2ad0f1b`: same parent offsets and lengths. |
| Initial wrapped storage | `0x2acd0b6..0x2acd2fd`: P `+0x2b0 -> +0x11b8`; then S `+0x23d8 -> +0x3d0 -> +0x51e8`; finally P `+0x2148`. | `0x2ad0f83..0x2ad11ca`: P `+0x2b0 -> +0x11b8`; then S `+0x3330 -> +0x3a0 -> +0x51c8`; finally P `+0x2148`. |
| Selected context storage | `0x2acd3b3`: `0x98` bytes from P `+0x20b8` to P `+0x2160`, preserving the word at P `+0x21f0`. | `0x2ad1411`: same parent copy coordinates. |
| Tail forwarding | `0x2acdb8c`, `0x2acddfb`, `0x2acdffe`, `0x2ace028`, `0x2ace041`, `0x2ace085`: six `0x88` copies carry P `+0x21f0` through S `+0x2a8, +0x2200, +0x2340, +0x220, +0x22b8` to S `+0x2b8`. | `0x2ad1aaa`, `0x2ad1e15`, `0x2ad2017`, `0x2ad2042`, `0x2ad205c`, `0x2ad20a1`: corresponding S positions `+0x278, +0x21d8, +0x2318, +0x1f0, +0x2290, +0x288`. |
| Admitted object copy | `0x2ace564`, `0x2ace57e`, `0x2ace5ba`: S `+0x2b8 -> +0x360 -> +0x2210`, then P `+0x220`, which is field `+0x90` of the object at P `+0x190`. | `0x2ad2582`, `0x2ad259c`, `0x2ad25d8`: S `+0x288 -> +0x330 -> +0x21e8`, then P `+0x220`. |
| Sender-phase storage | `0x2ace675`, `0x2ace690`, `0x2ace6a7`, `0x2ace6f8`, `0x2ace84a`, `0x2ace8dd`, `0x2ace8ed`: seven further copies reach P `+0x11a8`. | `0x2ad2693`, `0x2ad26ae`, `0x2ad26c5`, `0x2ad2716`, `0x2ad2862`, `0x2ad28f5`, `0x2ad2905`: seven copies reach the same relative location. |

The `0x88` tail copies start at context `+0x10`; the tracked word is their
offset `+0x80`. The reconstructed selected output has its first two QWORDs
stored separately at A `0x2ace05b/0x2ace068` or B `0x2ad2077/0x2ad2084`.
The tail then enters output `+0x10`. Guards at `0x2ace043..0x2ace047` and
`0x2ad205f..0x2ad2063` admit the selected unsigned tag values at most 1;
the higher-tag branch leaves this route. Earlier checks and helper returns
remain additional conditions, not implied successes.

For the last seven edges, the concrete copy lengths are
`0xf10, 0x1eb0, 0x1eb0, 0xf10, 0xf10, 0xf80, 0xf80`.
In A the word moves through S `+0x12e0`, S `+0x60f8`, P `+0x20b8`,
S `+0x4268`, S `+0x3d0`, S `+0x3358`, P `+0x11a8`.
In B those positions are S `+0x12b0`, S `+0x60d8`, P `+0x20b8`,
S `+0x4248`, S `+0x3a0`, S `+0x2420`, P `+0x11a8`.

The prior [ABCI greeting evidence](../RE-017-abci-greeting-115/README.md)
already documents A's last seven copies for a different pointer and mode byte.
This follow-up rebinds their bytes to #115, tracks the context's two-byte field,
extends backward to the selected initial input, and separately checks B.
It does not claim those copy instructions as newly discovered functions.
The existing [acquire/release caller packet](../RE-001-node115-lu-acquire-release-callers/README.md)
covers another operation in these same bodies; no change to that work is made.

All selected copy calls resolve through unique GLOB_DAT slot `0x64df508`,
dynamic symbol `memcpy`, with zero addend. For retained-register calls the
collector pins both the call register and its selected RIP-relative load;
preservation across the intervening selected path and SysV callee returns is
an explicit premise. Manual source/destination annotations are not presented
as an automated whole-CFG register proof. Six state-zero dispatch entries
are bound, covering the entry, intermediate and sender-phase tables in A/B;
no full table domain or all-state transition system is inferred.

## Direct operands, outgoing references and cleanup

Across each complete caller interval, the syntactic inventory finds eight
`lea ..., [rbx+0x1118]` instructions. Three feed the sender paths described in
[ROUTE-MAP](ROUTE-MAP.md); five immediately precede calls to `0x2ab9750`:

| Caller | Cleanup call VAs |
| --- | --- |
| A | `0x2acf2f2`, `0x2acfb06`, `0x2ad078b`, `0x2ad0b1d`, `0x2ad0d48` |
| B | `0x2ad32bf`, `0x2ad3b2b`, `0x2ad4798`, `0x2ad4b2a`, `0x2ad4d4f` |

There are **zero explicit RBX-plus-constant memory operands overlapping
`[parent+0x11a8, parent+0x11aa)`** in either caller's full decoded interval.
This is deliberately narrower than a write census. It excludes indirect
aliases, memcpy effects and writes in callees. LEA only computes an address.
The separate QWORD store/read at parent `+0x1120` belongs to earlier storage
use; its presence is another reason not to assign one live context layout to
this region throughout the entire routine.

The complete 184-byte cleanup helper retains its input in RBX, calls
`0x26ead80`, loads the DWORD at object `+0x18`, compares it with `-1`, and
conditionally calls the imported `close` via unique GLOB_DAT slot `0x64dfe78`.
It then calls helpers with object base and offsets `+0x60`, `+0x78`, `+0x20`
and `+0x40`; corresponding landing-pad paths are also retained. This supports
a resource-cleanup interpretation. The initial helper, nested effects and
unwinding behavior are not fully reconstructed. No absence-of-mutation claim
is inferred from the cleanup helper's own lack of a direct `+0x90` store.

## Verification and limits

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/members.py --out work/context-members-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/members.py --out work/context-members-optimized
```

Use fresh directories and the Python/Capstone/GNU/LLVM versions recorded in
[members/versions.json](members/versions.json). Commands are retained in
[members/commands.json](members/commands.json). Earlier packet collectors
still validate their own claims; this supplement does not replace them.

The full target digest, three FDE bounds/body hashes, 96 anchor spans, actual
copy-length instructions, selected imports/call registers and six dispatch
entries are checked. GNU/LLVM byte partitions cover the full **32,655 bytes /
5,890 Capstone rows**; raw A/B exports equal those retained in the previous
follow-up. The newly exported cleanup interval accounts for only 184 bytes /
49 rows. These are export sizes, not reconstruction coverage. LOCK-prefix
partition joins are recorded; there are no byte masks or asserted semantic
agreement between decoders.

All **156 controls** reject the intended changes: 96 anchor-byte mutations,
six dispatch mutations, four duplicate/changed parsed relocations, 48 interval
counterfactuals dropping the tracked word's second byte, and two shifted final
destinations. The last 50 check only interval algebra on the annotated copies;
they are not binary mutations, target execution or independent behavior tests.
Normal and optimized Python produce identical retained outputs. Overlapping
anchor spans are not independent discoveries.

Fresh doctor, artifact/import verification, four greeting-deadline tests and
literal reproduction passed. Catalogue checking still reports stale generated
README content. The earlier full suite remains incomplete with the failures
recorded in [validation.json](validation.json); it was not rerun or relabeled
as passing. Exact current results and log hashes are in
[members-validation.json](members-validation.json).

The bounded copy and direct-operand questions are answered. Full mutation and
lifetime closure remains open. Next, bind the initial context at P `+0` to
the caller/factory path and inspect the helpers receiving the intermediate
context at P `+0x2160`, including resumed states. The ABCI greeting packet's
executor/factory addresses are leads for the former, requiring new field-specific
checks. Preserve the distinct outgoing/local-port roles established earlier.
The subsequent [factory follow-up](FACTORY-JOIN.md) now supplies that selected
accepted-context join for large caller A through two executor branches; it
does not close the helper-mutation premises or twin B's initial origin.
No typed Rust object, whole-node implementation, behavioral equivalence or
acceptance gate is claimed. All 92 gates remain false. No captured executable,
emulator, live socket, commit, push or external submission is used.

New analysis/scripts are independently authored MIT work. Existing captured
bytes and evidence retain their upstream terms.
