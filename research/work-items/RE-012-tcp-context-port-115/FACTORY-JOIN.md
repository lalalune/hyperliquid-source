# RE-012: accepted context through the two executor factories

- Component/task: transport / RE-012, with RE-001 address/data bindings.
- Sole target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Status: conditional static field-provenance join, not runtime validation.
- Owned files: this evidence directory only; no shared tools, imported inputs,
  submodule pins, Rust implementation or acceptance gates are changed.

## What this closes

The selected accepted-context constructor output at `+0x90` reaches the
initial input at `+0x90` of large caller **A, `0x2accee0`**, through either of
two executor factory paths, under the explicit helper/alias/scheduling premises
below. Both factories reach A; they do **not** establish the initial origin of
twin large caller B, `0x2ad0db0`.

This fills the copy/offset gap between [ROUTE-MAP](ROUTE-MAP.md)'s listener-side
constructor and [MEMBER-LIFETIME](MEMBER-LIFETIME.md)'s selected A input-to-member
relation. The same two-byte value can consequently be followed through that
conditional relation to A's context member `+0x1118`, field `+0x90`.
The earlier listener route supplies requested local bind word **3999**. If
all these premises hold, that low word reaches the already established
sender eligibility exclusion. This is not proof that a captured node run
executes the route or that any live send/compression operation succeeds.

The existing [ABCI greeting packet](../RE-017-abci-greeting-115/README.md)
provided executor/factory leads for another field (`+0x138`). This follow-up
checks the `+0x90` word against original #115 bytes and independently checks
the six executor intervals. No previous code or progress credit is transferred.

## Accepted context to child input

All addresses are linked ELF VAs before load bias. `AS` is the acceptor's
post-prologue stack, `AP` its state base, `AO` its return-output pointer, and
`OS` the outer routine's separate stack. Byte anchors, actual copy-length
instructions and selected call bindings are in [factory-spec.json](factory-spec.json).
Full per-copy coordinates are in [factory/records.json](factory/records.json).

At `0x2afb7ae..0x2afb7c7`, acceptor `0x2afae20` reads DWORD
`[QWORD[AP+0xd8]+0x20]` into ECX and calls constructor `0x4784d00` with output
`AS+0x110`. The constructor saves ECX in EBP and writes **WORD**
`[out+0x90] = BP` at `0x4784da7`. Thus the tracked word starts at `AS+0x1a0`.
No initialization claim is made for the neighboring two bytes.

| Copy call | Source / destination base and length | Tracked word after copy |
| --- | --- | --- |
| `0x2afb7fd` | AS `+0x120 -> +0x230`, `0x88` bytes | AS `+0x2b0` |
| `0x2afb815` | AS `+0x230 -> +0x1a8`, `0x88` bytes | AS `+0x228` |
| `0x2afb705` | AS `+0x1a8 -> AP+0x18`, `0x88` bytes | AP `+0x98` |
| `0x2afb75b` | AP `+0x8 -> AO+0`, `0xb8` bytes | AO `+0x90` |
| `0x2ad5e25` | OS `+0x370 -> +0x2d8`, `0x98` bytes | OS `+0x368` |
| `0x2ad5e58` | OS `+0x2d8 -> +0xf8`, `0x98` bytes | OS `+0x188` |
| `0x2ad6140` | OS `+0xf8 -> +0x190`, `0x98` bytes | OS `+0x220` |
| `0x2ad6196` | OS `+0x190 -> +0x3390`, `0x148` bytes | OS `+0x3420` |
| `0x2ad6307` | OS `+0x3390 -> +0x9390`, `0x2ff8` bytes | OS `+0x9420` |

The acceptor stores its return pointer at `AS+0x90` at `0x2afae3c`, then
reloads it at `0x2afb753`. Outer routine `0x2ad5980` supplies that pointer as
`OS+0x370` at `0x2ad5ded..0x2ad5dfd`, so `AO+0x90` is `OS+0x400` before
the first outer copy. AP `+0x98` is context-relative `+0x90`, since the
returned context starts at AP `+0x8`.

The selected route excludes constructor tag 3 at `0x2afb840..0x2afb844`,
acceptor tag 2 at `0x2afb740..0x2afb744`, and outer result tag 2 at
`0x2ad5e02..0x2ad5e0a`. The outer WORD test at `0x2ad605a` concerns the
separate returned address tag: its equal-to-1 branch cleans up and returns to
accepting, rather than dispatching this context. The accepted peer address
remains separate from the constructor ECX field, as established earlier.
These are selected branch conditions, not a proof of every legal state.

At `0x2ad6325` or `0x2ad633a`, RSI is `OS+0x9390`. The tracked location
`OS+0x9420` is therefore **child input `+0x90`**. The outer thread/executor
checks select one adapter; rejected and unavailable-executor branches do
not imply a child task was scheduled.
At this selection, R14 equal to 2 takes the excluded branch; otherwise
R14D equal to 1 selects executor A, and the other branch selects executor B.
The complete domain of R14 is not established by these tests.

## The two executor paths

| Stage | Executor path A | Executor path B |
| --- | --- | --- |
| Adapter | `0x2b3f300`, call `0x2b3f328 -> 0x2cd1070` | `0x2b403a0`, call `0x2b403cf -> 0x2cd1970` |
| Input copy | `0x2cd1123` | `0x2cd1a23` |
| Stack repack | `0x2cd1189` | `0x2cd1a89` |
| Allocation copy | `0x2cd11d8` | `0x2cd1ad8` |
| Descriptor slot zero | `0x6449600 -> 0x2b1d9a0` | `0x6449790 -> 0x2b26920` |
| Poller-to-large-A call | `0x2b1db89 -> 0x2accee0` | `0x2b26b09 -> 0x2accee0` |

Each adapter leaves incoming RSI unchanged on the normal pre-constructor
path. Each constructor first copies `0x2ff8` bytes from that child input to
its own stack `+0x3158`: word `+0x90` becomes stack `+0x31e8`. It then copies
`0x2ffc` bytes from stack `+0x3154` to stack `+0xb4`, moving the word to
stack `+0x148`. Finally, a `0x3080`-byte copy from stack `+0x80` to the
successful allocation puts the word at **allocation `+0xc8`**.

The stack repack begins four bytes before the first input copy. Tracking the
word does not establish those four bytes, all copied padding, or a complete
initialized Rust object. The two constructors have different frame instances;
their equal relative offsets do not identify the stack regions with each other.

Each descriptor pointer is stored at constructor stack `+0x90`, becoming
allocation `+0x10`. Its slot zero is a unique RELATIVE relocation to the
listed poller. The pollers form RDI as allocation `+0x38` at `0x2b1db7b`
and `0x2b26afb`. Their direct calls both enter **large A `0x2accee0`**.
Allocation `+0xc8` is hence large-A input `+0x90`.

All 15 distinct selected copy-call sites use unique GLOB_DAT slot `0x64df508`,
symbol `memcpy`, zero addend. Retained-register forms pin both the relevant
load and call; preservation across the intervening selected path is a stated
SysV/helper premise. Each executor path uses nine common copies and its
three constructor copies, for twelve copy calls along that selected path.
Do not count these as twelve independently observed runtime transfers.

## Premises and unresolved behavior

The conditional join requires readable/writable nonoverlapping copy regions,
normal imported-copy behavior, the selected branch conditions, and no
conflicting writes through aliases or helpers to the tracked bytes. In
particular, it does not prove preservation across:

- Accept-state cleanup `0x2a9dcd0` at `0x2ad5e3e` and other outer helpers.
- Constructor post-copy helpers `0x2cd0910` / `0x2cd06c0`, which receive the
  allocation before its eventual use by the poller.
- Adapter scheduling/callback paths and poller helpers before the large call.
- The scheduler dispatching each descriptor with the allocation that stores
  it, without moving or altering the tracked bytes.

Static descriptor targets are not a scheduling proof. A copy-preserved port
word also does not prove the referenced socket/resources remain usable.
The later [helper-write supplement](HELPER-WRITES.md) narrows the constructor
helper premise on selected call-free, uncontended insertion paths only;
contended/nonzero-flag branches, aliases and concurrency remain unresolved.
The [poll-prefix supplement](POLL-PREFIX.md) additionally narrows pre-call
mutation for dispatch-zero, TLS-1/2 paths with the selected successful CAS;
it does not establish scheduler invocation identity or the other TLS path.
All legal resumed states, exceptions, destructor effects, alias ownership and
the initial source of twin large B remain open. No original Rust type name,
typed object layout, whole-node build or equivalence is claimed.

The subsequent [accepted-state cleanup join](CLEANUP-JOIN.md) resolves the
`0x2a9dcd0` call on the selected tag-1 path: it has no object writes or nested
calls, and its register-save stack stores miss the copied word. This retains
the preceding memcpy, state/stack disjointness and ABI premises; other cleanup
states and outer helpers remain open.

## Reproduce and check

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/factory.py --out work/context-factory-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/factory.py --out work/context-factory-optimized
```

Use fresh directories and the versions in [factory/versions.json](factory/versions.json).
Native commands are retained in [factory/commands.json](factory/commands.json).
The collector authenticates the complete target and checks nine complete FDE
intervals, **11,259 bytes / 2,306 Capstone rows**, 40 anchor spans, seven direct
calls, the constructor slot, both descriptor slots, and the memcpy import.
Six executor intervals account for **4,356 bytes / 934 rows**; the other three
intervals are rechecked context from the preceding packet. FDE/export sizes
are not recovered function coverage or source-equivalence credit.

GNU/LLVM exports cover every byte and agree with Capstone instruction
boundaries except for the recorded LLVM standalone LOCK-prefix joins. There
are no byte masks; semantic decoder agreement and full CFG completeness are
not asserted. Normal and optimized runs produce identical files.

All **69 controls** reject the intended change: 40 anchor-byte mutations,
eight changed/duplicate parsed relocation records, 15 interval counterfactuals
dropping the tracked word's second byte, four shifted interval endpoints, and
two invalid target inputs. The last 19 interval checks are arithmetic over
manual annotations, not execution/emulation or mutation of target instructions.
Byte-pin controls bypass the outer digest only in memory; normal collection
always authenticates the complete input.

The prior route and member collectors were rerun and their outputs compared
with the retained evidence. Fresh doctor, artifact/import verification,
four greeting-deadline tests and literal reproduction passed. Catalogue
checking still fails on stale generated README content. The full-suite
failures/incomplete run in [validation.json](validation.json) remain in force;
this bounded follow-up does not claim a passing whole suite. Current results,
review scope and raw-log hashes are in [factory-validation.json](factory-validation.json).

The next concrete question is whether the two post-copy constructor helpers
can write allocation `+0xc8`, followed by mutations on the selected poll path.
That work would narrow a named premise without expanding into scheduler
architecture work. No captured code, socket, key or chain action was run;
no commit, push, PR or external message was published. All 92 gates stay false.
New analysis/scripts are MIT; existing bytes retain their upstream terms.
