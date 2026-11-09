# RE-012 follow-up: sender inputs and the listener-side port field

Sole target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
Owned files: this evidence packet only. No implementation or milestone gate
is changed. No captured code is executed or emulated.

## Result and bounded question

The field at context `+0x90` must not be named universally `destination_port`.
The earlier outgoing route gives it the selected connect destination port.
On the accepted-side construction route below, its low word instead comes
from the **requested local bind port**, with a concrete initial value of
**3999**. The accepted peer address follows separate instructions and storage.
This does not assert that the two ports could never happen to be equal.

This follow-up answers two bounded questions: which context pointers reach the
remaining encoded calls to sender `0x2b7a290`, and which inputs reach constructor
`0x4784d00`? It identifies the six sender sites and five constructor sites in
the specified encoding census, and traces one listener word into construction.
It does **not** close the complete constructed-object-to-sender graph, every
legal resume path, aliases, helper effects or scheduler behavior.

## Encoded call-site census

[routes.py](routes.py) scans all `.text` bytes for E8/E9 transfers directly to
the sender or constructor and RIP-relative FF15/FF25 transfers through the
constructor's selected relocation slot. Candidates must be instruction starts
in completely decoded FDE intervals. The only RELATIVE relocation whose
addend is the constructor is slot `0x64e7540`; its entry is unique.
The observed sites below are calls, with no additional validated jump sites.

This census excludes arbitrary register calls, other vtable/address-taking
mechanisms, alternate instruction encodings and code outside `.text`.
It is not an exhaustive whole-program caller graph. FDE intervals provide
export bounds, not recovered source-level function identities.

| Sender call VA | Enclosing FDE start | Context pointer supplied on the selected path |
| --- | --- | --- |
| `0x2ad03b2` | `0x2accee0` | `parent+0x1118`, stored at `parent+0x1298`; sender base `parent+0x1288`. |
| `0x2ad43da` | `0x2ad0db0` | Same relative member/store/base as the preceding site. |
| `0x2ae3ddd` | `0x2ae3cc0` | Input pointer from child `+0x18`, retained at `+0x388`, stored at sender-context slot child `+0x80`; sender base child `+0x70`. |
| `0x2b684b5` | `0x2b67e50` | Caller `+0x148`; the first outgoing route in [README](README.md). |
| `0x2b6a6a6` | `0x2b69d20` | Caller `+0xa0`; the outgoing port-4002 route in [SECOND-CALLER](SECOND-CALLER.md). |
| `0x2b7a1b7` | `0x2b7a140` | Wrapper input `+0x340` copied to `+0x38`; sender base wrapper `+0x28`. |

The two large parents also pass `parent+0x1118` to the wrapper by writing
`parent+0x15c0` and calling it at base `parent+0x1280`. The relevant setup/call
pairs are `0x2acecaf..0x2acecde` and `0x2ad2c85..0x2ad2cb4`.
For the follow-up path they place the same pointer at `parent+0x12b0`, the
`+0x20` input of intermediate base `parent+0x1290`, at `0x2acf0d2..0x2acf0d9`
and `0x2ad30a5..0x2ad30ac`. Calls at `0x2ace9ba` and `0x2ad29c3` target
intermediate `0x2ae27c0`.

That intermediate retains its `+0x20` input at `+0x28`. At `0x2ae2f6c` and
`0x2ae337d`, it loads that retained pointer and writes it to `+0x18` of child
bases `+0xc8` and `+0xa8`, respectively. Calls at `0x2ae2fc1` and `0x2ae33cb`
then enter `0x2ae3cc0`. Initial and selected retained-pointer instructions are
pinned; this does not establish the legality of every re-entry state.
The construction and mutation history of large-parent member `+0x1118`
remains open. Its name and value cannot be inferred from these pointer copies.
The subsequent [member-lifetime follow-up](MEMBER-LIFETIME.md) adds the
selected input-to-member copy relation and cleanup references; it retains
the unresolved helper/alias and all-state mutation boundary.

| Constructor call VA | ECX source before the call | Established interpretation |
| --- | --- | --- |
| `0x2b7877d` | Zero-extended WORD `[producer+0x26]` | Earlier selected outgoing destination-port route. |
| `0x5ab41c4` | Zero-extended WORD `[producer+0x26]` | Same input offset and width; its complete socket-helper route is not established here. |
| `0x2afb7c7` | DWORD `[QWORD[producer+0xd8]+0x20]` | Selected listener route below supplies its low word. |
| `0x2cc0cbb` | DWORD `[QWORD[producer+0xf8]+0x20]` | External record field; upstream construction not closed here. |
| `0x5a60328` | DWORD `[QWORD[producer+0x988]+0x20]` | External record field; upstream construction not closed here. |

All five call sites resolve to the same constructor, which retains ECX in EBP
at `0x4784d0a` and writes **WORD** `[out+0x90] = BP` at `0x4784da7`.
The upper half of any input DWORD is not part of this store. No zero-padding
assumption is justified for context `+0x92/+0x93` or the external record.

## Requested local bind port 3999: conditional provenance

All addresses and copies below are retained in [routes-spec.json](routes-spec.json)
and full raw exports under [routes/](routes/). Names such as builder, outer and
acceptor describe these observed operations; they are not recovered Rust types.

| Stage | Original instruction evidence | Relationship |
| --- | --- | --- |
| Initial selection | `0x2aecd6a..0x2aecd8f` | Parent writes WORD `+0xcac = 6` and calls builder `0x2a64130` with base parent `+0xb18`. This supplies index byte 6 at builder `+0x194` and zero initial-state byte at `+0x195`. |
| Address word | `0x2a64168..0x2a641a6` | Loads index, selects WORD from table `0x607018`, stores tag zero and IPv4 address zero, and stores selected WORD at address `+6`. Index 6 selects bytes `9f 0f` at `0x607024`, value 3999. |
| Retained and working copies | `0x2a64209..0x2a64244`, `0x2a64722..0x2a6481a` | Self-pointer through builder `+0x20/+0x68` leads to 32-byte address copies. Retained address starts at `+0xf0`; working copies supply helper input on stack `+0x20`. |
| Bind and listen arguments | `0x475b491..0x475b4dc` | Helper loads input WORD `+6`, rotates AX by 8, stores it at sockaddr `+2`, and passes family 2 / length 16 to imported `bind`, followed on success by imported `listen`. |
| Retained result word | `0x2a649dd..0x2a64a0e`, `0x2a6487f` | Selected bind/registration-success path loads retained WORD `+0xf6` for tag zero and stores it at builder `+0xb8`. |
| Builder return | `0x2a64a35..0x2a64aa8` | The result tail copies this word through stack `+0xd0` to result `+0x20`. Only its low two bytes are established; QWORD copy width does not establish all copied bytes. |
| Parent handoff | `0x2aecd94..0x2aecdd9`, `0x2aecf44..0x2aecf5d` | After excluding output tag 2, copies the 40-byte result to stack `+0x3210` and passes that address as the second argument to `0x2ad5600`. |
| Future storage | `0x2ad578b..0x2ad583f` | Factory copies those 40 bytes to stack `+0x80`, including the word at `+0xa0`; a `0x340`-byte `memcpy` from that base preserves it at allocated-object `+0x20`. It passes allocation and vtable `0x64478d8` to helper `0x15d6730`. |
| Selected poll linkage | Relocation `0x64478f0`; `0x2ad5dcb..0x2ad5dfd` | Vtable slot `+0x18` resolves to outer routine `0x2ad5980`. If dispatched with that allocation, it stores its base pointer at outer `+0x258`, the `+0xc0` input of child base outer `+0x198`, then calls `0x2afae20`. |
| Acceptor retention | `0x2afae5b`, `0x2afb168..0x2afb19f` | Retains child input `+0xc0` through child `+0xd0/+0xd8`. |
| Constructor input | `0x2afb7ae..0x2afb7c7` | Loads the retained pointer, reads DWORD `[outer+0x20]` into ECX, then calls the constructor. Its WORD store at context `+0x90` preserves the requested local word 3999. |

The bind helper at `0x475b3f0` is selected by unique RELATIVE slot
`0x64e70a8`. Its imports bind to unique GLOB_DAT entries with zero addends:
`socket` at `0x64e8a10`, `setsockopt` at `0x64e1410`, `bind` at `0x64e8a20`,
and `listen` at `0x64eb070`. The selected copy slot `0x64df508` resolves to
`memcpy`. Names come from the ELF dynamic symbols, not nearby-symbol labels.

The local-address interpretation uses the observed argument construction and
the Linux [bind](https://man7.org/linux/man-pages/man2/bind.2.html) and
[listen](https://man7.org/linux/man-pages/man2/listen.2.html) contracts.
It is a **requested** bind port, not an observed socket address, a successful
live listener, or evidence about port-zero assignment/`getsockname` behavior.

At `0x2afb455` the accept-side producer calls `0x475b050`; its returned address
is handled separately from the retained listener pointer. The selected IPv4
branch shifts the packed address at `0x2afb779` and `0x2afb7cd`, then saves
address bytes/word at producer `+0xa2/+0xa6` at `0x2afb714/0x2afb71a`.
The constructor ECX load uses the external `+0x20` field instead. Neither this
separation nor constructor-call similarity proves the origin of every other
accept-side context. The existing
[accept-source proof](../RE-012-accept4-source-115/PROOF.md) supplies the helper's
raw address contract. Its static records were freshly regenerated against
#115 and matched; its source-build/registration claims remain separate.

The route assumes selected normal bind/registration/allocation returns,
ordinary imported-copy behavior, valid nonoverlapping storage, no conflicting
alias writes, and the indicated future being polled with its own allocation.
The scheduler helper and all allocation/error/unwind paths are not reconstructed.
The listener-to-constructor chain must not be silently extended to all six
sender sites or to a complete compression outcome.

## Reproduction and validation boundary

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/routes.py --out work/context-routes-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/routes.py --out work/context-routes-optimized
```

Both directories must be fresh. Use the versions and native commands in
[routes/versions.json](routes/versions.json) and
[routes/commands.json](routes/commands.json). Run the earlier collector and
verifier from [README](README.md) for the original routes as well.

The new collector exports 15 complete FDE intervals: **88,541 bytes / 16,330
Capstone instruction rows**, with GNU and LLVM exports for each interval.
Some intervals and pins overlap earlier evidence; these numbers are not new
function coverage or independent semantic observations. Native comparisons
check complete byte coverage and instruction boundaries, joining explicitly
counted standalone LLVM LOCK prefixes; they do not prove operand semantics
or a complete CFG. No byte normalization masks are used.

There are **83 selected anchor spans** and **109 rejected controls**: 83 byte
mutations, six dispatch-entry mutations, eighteen changed/duplicate relocation
records and two parsed-census missing/extra-site counterfactuals. Overlapping
anchors are intentional and not counted as independent route discoveries.
The byte controls bypass the outer digest only in memory; normal collection
authenticates the full target. Census counterfactuals test the expected-set
check, not discovery of arbitrary indirect transfers.

Normal and optimized runs produced identical retained files. Fresh doctor,
artifact/import/packet verification, the existing greeting-deadline tests and
literal reproduction passed. Catalogue checking still fails on the pre-existing
stale generated README. A separate full replay of the existing accept-source
packet failed its `one selected accept interval` registry check; the fresh
static-record comparison passed, which is the scope reused here. The earlier
full suite was incomplete with Windows
failures and an interrupted expensive test; it was not rerun or declared green.
See [routes-validation.json](routes-validation.json) and the preserved earlier
[validation.json](validation.json) for exact scope and raw-log hashes.

The next reconstruction question is the origin and mutation history of
large-parent member `+0x1118`, followed by the remaining external-record `+0x20`
producers. Keep the selector's generic u32 input and use neutral field labels
until the relevant object layouts and all supported paths are established.
No Rust implementation, behavioral equivalence, source-build identity or
whole-ELF comparison is claimed. All 92 component gates remain false.

New analysis/scripts are independently authored MIT work; captured bytes keep
their existing terms. No commit, push, PR or external review comment was made.
