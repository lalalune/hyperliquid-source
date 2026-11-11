# RE-012: preserving the context word up to the large caller

- Component/task: transport / RE-012, with RE-001 address/data bindings.
- Sole target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Status: conditional static pre-call write relation, not runtime validation.
- Owned files: `poll.py`, `poll-spec.json`, `poll/`, this report,
  `poll-validation.json`, packet links and manifest. No shared tooling,
  imported evidence, Rust implementation or acceptance gate is changed.

## What this narrows

Both selected pollers have paths from their entry to the first call of
`0x2accee0` with **no earlier function call**. The conditions include the
selected successful header CAS, dispatch index zero, DWORD `P+0x30 == 0`,
and TLS flag 1 or 2. On these paths the sole explicit write into allocation
P is the eight-byte header update at **`P+0`**. Other writes go to the stack
and, for TLS flag 1, a TLS slot. Thus their own writes preserve the tracked
word at **`P+[0xc8,0xca)`**, subject to separate valid stack/TLS storage and
absence of interfering concurrent writes.

At the call, RDI is `P+0x38`, so large caller A's input field `+0x90`
addresses the same two bytes: `0x38+0x90=0xc8`. This narrows the pre-call
mutation premise of [FACTORY-JOIN](FACTORY-JOIN.md), following the separate
constructor-helper result in [HELPER-WRITES](HELPER-WRITES.md).

It does not establish that the scheduler actually invokes the poller with
the same still-live allocation. Nor does it establish behavior after the
large call, all TLS states, retry histories, exceptions, or intervening
writes between the constructor/helper and poll entry.

## Original bounds and dispatch

All addresses below are linked ELF VAs before load bias. Exact FDE bounds,
file offsets, body hashes, LSDA addresses, raw GNU/LLVM exports and decoded
transfers are retained in [poll/records.json](poll/records.json).
FDE bounds are selected disassembly extents, not a whole-node function count.

| Binding | Poller A | Poller B |
| --- | --- | --- |
| Full FDE interval | `[0x2b1d9a0,0x2b1df5b)` | `[0x2b26920,0x2b26eaf)` |
| Descriptor slot zero | `0x6449600` | `0x6449790` |
| Header CAS on selected path | `0x2b1da22` | `0x2b269a2` |
| Relative dispatch table | `0x604524` | `0x604784` |
| Indirect dispatch | `0x2b1da65` | `0x2b269e5` |
| Check DWORD `P+0x30` | `0x2b1da94` | `0x2b26a14` |
| TLS registration call on excluded path | `0x2b1db62` | `0x2b26ae2` |
| Form RDI=`P+0x38` | `0x2b1db7b` | `0x2b26afb` |
| Call large A | `0x2b1db89 -> 0x2accee0` | `0x2b26b09 -> 0x2accee0` |

The prologues retain input RDI in RBX=P and read QWORD[P] into RAX.
For a header value A satisfying `(A & 7) == 4` and `(A & 0x20) == 0`, the
selected CAS attempts to replace A with `(A & ~7)+1`. On success, the
dispatch index from `(low_byte(A) >> 5) & 1` is zero. The existing
constructors initialize QWORD[P] to `0xcc` and DWORD[P+0x30] to zero;
their pinned stack stores and allocation copy are revalidated. If that
header is still present, the CAS replacement is **`0xc9`**. Its continued
presence at a later poll is a premise, not an observed runtime state.

The table entries are signed 32-bit offsets relative to each table base.
All four selected entries, their raw bytes, lack of relocations, and target
instruction boundaries are checked:

| Index | Table A target | Table B target |
| --- | --- | --- |
| 0 | `0x2b1da67` | `0x2b269e7` |
| 1 | `0x2b1dad6` | `0x2b26a56` |
| 2 | `0x2b1ddf8` | `0x2b26d4c` |
| 3 | `0x2b1dce6` | `0x2b26c3a` |

Only index zero belongs to this preservation path. Other entries lead to
calls or return before the selected large-call site. Four entries are
recorded because of the encoded dispatch paths; no wider table extent or
whole-function indirect-control-flow completeness is claimed.

## TLS state and write inventory

After the zero DWORD check, the code loads RBP=`QWORD[P+0x28]`, sets
R12=`-0x1130`, and reads the flag at `FS.base-0x10e8`.

| Flag | Before calling `0x2accee0` |
| --- | --- |
| 1 | Save the old QWORD at `FS.base-0x1100` in R13, then replace it with RBP |
| 2 | Set R13=0 and skip the TLS-slot write |
| Other | Call `0x5ca0d20`, write flag 1 after return, then take the flag-1 path; excluded from the no-prior-call result |

The flag meanings beyond these encoded branches are not inferred. The
selected TLS-1 store sites are `0x2b1db75` and `0x2b26af5`. Neither is an
allocation-relative store: the FS segment and signed R12 offset matter.
The stored value is copied from P+0x28, not from the tracked word.

The lexical intervals from each poll entry to its selected call contain
21 explicit memory destinations (42 total), including code on excluded
branches. These are classified from opcodes/operand widths, not decoder
access flags. The four selected paths have 13 or 14 explicit writes each:
12 stack writes, one header CAS, and the optional TLS write. Stack probes
occur at different RSP values; their recorded offsets do not mean a single
fixed stack slot. Pushes and the endpoint call's return-address write are
separate implicit stack effects covered by the valid, separate-stack premise.

The static traversal records 62 instruction addresses for TLS flag 1 or
64 for flag 2, including the final call as the stopping boundary. It checks
encoded conditional/direct edges and resolves the selected table entry.
It executes no instruction or target code and simulates no registers or
memory. Register-to-region and field-offset joins are manually reviewed
annotations; this is not an automated alias/value proof. The header worksheet
corroborates the mask arithmetic for all 256 low bytes and the `0xcc` case;
it is not an independent observation of captured behavior.

## Immediate helper on the other TLS path

The call at either TLS-registration site uses relocation
`0x64e0510 -> 0x5ca0d20`. The caller supplies
`RDI = QWORD[FS:0] - 0x1130` and `RSI = 0x5cdf410`.
This statement does not assume `QWORD[FS:0]` equals FS.base; the direct
segment-relative accesses above and the loaded pointer are kept distinct.

The complete helper interval `[0x5ca0d20,0x5ca0e1f)` is exported (255 bytes,
58 instructions). Observed branches are:

- If the pointer at `0x64ec9b0` is nonzero, tail-dispatch through it after
  setting arguments to the supplied callback, supplied object pointer and
  `0x64fe448`. Its unique GLOB_DAT relocation names
  `__cxa_thread_atexit_impl`. The symbol binding supports a TLS-destructor
  registration interpretation; the external implementation is not analyzed.
- Otherwise, the fallback examines TLS storage, calls `0x5ca0e20`, and may
  call `0x5c8b620` through `0x64ec878`. It writes a 16-byte pair consisting
  of the supplied object pointer and callback into storage loaded from TLS,
  increments its count and updates TLS bookkeeping. Those effective storage
  addresses and transitive callees remain unclosed.
- The alternate/error path calls `0x5cad560`, `0x5c731f0`, and a relocated
  target `0x5c9b050`; unwind transfer is also recorded. Nonreturn contracts,
  exceptions and callback execution/lifetime are not proved here.

No explicit P argument is supplied to this helper, but that alone cannot
prove absence of alias/global writes to P. The flag-other path remains an
open premise. Likewise no semantics are transferred from a similarly named
public runtime without target-specific validation.

The later [TLS write-region join](TLS-WRITES.md) freshly validates the
existing key/growth/allocation evidence and maps the remaining local writes
and imported boundaries. It makes TLS-self identity and list/storage
conditions explicit; it does not promote this branch to unconditional closure.

## Reproduce, checks and remaining work

Use Python 3.12 with Capstone 5.0.7, GNU objdump and llvm-objdump on PATH,
from the repository root and with fresh output directories:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/poll.py --out work/context-poll-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/poll.py --out work/context-poll-optimized
```

The collector authenticates the entire target, checks five complete FDE
intervals (**4,115 bytes / 858 Capstone rows**), and retains versions,
commands and raw output in [poll/](poll/records.json). The two pollers account
for 2,890 bytes / 610 rows; the other intervals are the TLS helper and two
constructors. These are export sizes, not reconstructed bytes or coverage.

GNU/LLVM outputs cover every byte and match Capstone instruction boundaries,
accounting for standalone LOCK-prefix splits. No normalization masks are used.
Normal and optimized outputs are byte-identical. Eight native exports for
the pollers/constructors also match the preceding factory packet exactly.
This checks partitions/boundaries, not complete semantic decoder agreement.

All **114 corruption/scope controls** reject their selected invalid input:
16 instruction-span mutations, eight changed dispatch entries, two injected
table relocations, 52 changed/duplicate parsed relocations, five truncated
FDEs, two damaged store inventories, ten excluded edges, six excluded
dispatch choices, five out-of-scope header cases, three excluded TLS states,
three overlapping write intervals and two wrong captures. Byte changes may
be rejected by full-body hashes before individual anchors. Scope controls
do not assert the excluded paths are impossible or invalid runtime behavior;
interval controls are arithmetic counterfactuals, not binary mutations.
Writes ending at `+0xc8` or starting at `+0xca` are accepted as nonoverlapping.

Fresh checks and raw-log hashes are in [poll-validation.json](poll-validation.json).
The prior helper and factory collectors were replayed and retained outputs
compared. Repository catalogue checking still reports stale generated README
content; the earlier incomplete full-suite result in [validation.json](validation.json)
remains in force. No hosted CI, full-suite success or new independent-agent
review is claimed.

The next bounded question is the TLS-registration fallback's callees
`0x5ca0e20` and `0x5c8b620` and their possible writes, to reduce the remaining
flag-other premise. Scheduler invocation identity, accept cleanup, large-A
helper effects and large B's initial source remain separate open questions.
No captured code, network, key or chain action was used. No commit/push was
made; all 92 gates remain false. New analysis/code is independently authored
MIT work, with original terms preserved for retained target bytes.
