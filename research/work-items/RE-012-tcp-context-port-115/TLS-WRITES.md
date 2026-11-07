# RE-012: TLS fallback writes and the tracked allocation field

- Component/task: transport / RE-012, using foundation / RE-001 evidence.
- Sole target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Status: static write-region and caller-domain joins with explicit contracts.
- Owned files: `tls-join.py`, `tls-join-spec.json`, `tls/`, this report,
  `tls-validation.json`, packet links and manifest. Shared tools, prior evidence,
  submodule revisions, implementations and acceptance gates are unchanged.

## Result and prior ownership

The two previously opaque fallback calls can be described more precisely:
`0x5ca0e20` manages a global pthread key, and `0x5c8b620` wraps the growth
installer and allocation-request helper. Their local write destinations can
be connected to the registration caller's global key word, stack scratch,
TLS list control and list entries. On the selected normal successful fallback
paths, the remaining called boundaries are the symbol-bound
`pthread_key_create`, `pthread_key_delete`, `pthread_setspecific`, `malloc`
and `realloc`. This is a call/write-region map, not a proof of those imported
implementations' behavior or runtime success.

All five bodies already have #115 evidence in the
[TLS fallback packet](../RE-001-node115-tls-fallback/README.md) and
[capacity-request packet](../RE-001-node115-capacity-request-layout/README.md).
They are freshly validated dependency context, with **zero new function-body
or source-comparison credit**. The new result is their field-specific join to
[POLL-PREFIX](POLL-PREFIX.md), including the required TLS-self-pointer identity,
the composed growth bound, and the exact append interval that must avoid
`P+[0xc8,0xca)`.

## Revalidated inputs and the host replay blocker

The original TLS `collect.py --check` and its 14-test suite were run unchanged.
The record check fails and the suite has one failure: ten native-capture path
strings use Windows backslashes while the retained record uses forward
slashes. A field-by-field comparison found no other difference after the
existing collector's Capstone-version allowance. Its 13 other tests, including
physical byte/relocation/FDE/LSDA corruption controls, pass in normal and
optimized Python. The original failure logs are retained; the suite is not
reported as green.

This blocked an exact metadata replay needed to reuse that packet. The local
`reference_check` in `tls-join.py` adapts only those ten capture-path metadata
fields and then requires full record equality. It does not edit the imported
collector/evidence, normalize native bytes, or suppress other differences.
The dependency's original structural and native checks still run. The separate
capacity verifier and its eight negative controls pass unchanged; its sizing
arithmetic check also passes. Input script/record/manifest hashes and the
exact metadata adaptations are retained in [tls/records.json](tls/records.json).
This small local adapter is confined to the active reuse check.

## Original addresses and writes

Addresses are linked ELF virtual addresses, before load bias. Fresh native
exports cover these complete FDE intervals; original file offsets, body hashes
and full call targets are in `tls/records.json`.

| Role | Interval | Bytes / instructions |
| --- | --- | --- |
| Registration caller | `[0x5ca0d20,0x5ca0e1f)` | 255 / 58 |
| Key initialization | `[0x5ca0e20,0x5ca0eea)` | 202 / 52 |
| Growth wrapper | `[0x5c8b620,0x5c8b649)` | 41 / 12 |
| Growth installer | `[0x5c8b980,0x5c8b9ee)` | 110 / 33 |
| Allocation request | `[0x5c8b8f0,0x5c8b980)` | 144 / 45 |

These **752 bytes / 200 instructions** are reused static context, not a new
whole-function inventory or reconstruction percentage. Seventeen explicit
memory destinations are inventoried across the full intervals, including
diagnostic/unwind sites. Implicit call/push stack effects and imported-function
writes are separate from this count. Classification uses opcodes and widths,
not decoder access flags.

The key helper reads `G = 0x64feda8`; its retained initial bytes are zero,
which does not establish its runtime value. A candidate nonzero key is
published with `lock cmpxchg QWORD[G]` at `0x5ca0e87`. Other local writes are
stack temporaries. The callback cell `0x64fedb0` has a unique RELATIVE target
`0x5ca53f0`, the already-recorded list-draining callback.

The helper's calls are symbol-bound at these slots:

| Slot | Symbol | Visible use |
| --- | --- | --- |
| `0x64ec9b8` | `pthread_key_create` | output key in stack temporary; callback from `0x64fedb0` |
| `0x64ec9c0` | `pthread_key_delete` | delete zero sentinel candidate or losing publication candidate |
| `0x64ec9c8` | `pthread_setspecific` | selected key and numeric value 1 |

The zero-key retry and competing-publication branches are retained from the
validated dependency packet. Key creation statuses are tested; delete and
setspecific statuses are not visibly tested. A return therefore does not
prove successful TLS registration or eventual callback execution. The
diagnostic helper chain is outside the selected normal paths.

## Joining growth to the caller's TLS list

Write `F` for FS.base and `T` for `QWORD[FS:0]`. These are distinct quantities
in the instruction evidence. The registration caller reads its list using
segment-relative addresses, but computes the growth argument from T:

| Item | Address/expression |
| --- | --- |
| Guard | `F-0x1150` |
| Capacity C | `F-0x1148` |
| Buffer B | `F-0x1140` |
| Count n | `F-0x1138` |
| Growth control H | `T-0x1148` |

At `0x5ca0d99..0x5ca0da5`, the code forms H and calls the wrapper through
`0x64ec878`. The wrapper loads RSI=`QWORD[H]` and calls `0x5c8b980` with
RDI still H. The installer reads old capacity from H and old buffer from H+8.
It calls `0x5c8b8f0` with a separate stack output, old capacity, old buffer,
and the requested new count. On a zero output tag it writes the returned
buffer to H+8 and new capacity to H; then the wrapper accepts sentinel
`0x8000000000000001`. Other returns dispatch to `0x141e264` through
`0x64df498`, whose error/nonreturn behavior is not proved here.

**H identifies the caller's TLS capacity/buffer only under `T == F`.** The
code shown does not establish that runtime identity. Without it, those two
stores target a different computed region and cannot be credited as writes
to the same TLS metadata. This is now an explicit premise of the join.

Under that identity and a valid list, the growth call occurs when n=C. The
literal arithmetic is `N = max((C+1) mod 2^64, (2*C) mod 2^64, 4)`. In the
admitted capacity domain `0 <= C <= 2^59-1`, neither addition nor doubling
wraps. The previously proved allocation gate accepts N iff `N <= 2^59-1`.
Composing the two therefore gives **C <= 2^58-1** for a full list whose growth
request passes the gate. This is a request-size bound, not proof that an
allocation of that size succeeds or is practical.

For C=0,1,2 the request is four entries (64 bytes); for C=3 it is six entries
(96 bytes). At C=`2^58-1`, the request is `2^59-2` entries and passes the
size gate; at C=`2^58`, the request is `2^59` entries and fails it. Eleven
boundary witnesses are retained. They evaluate equations pinned to target
instructions, not captured instructions or an allocator simulation.

The request helper calls `malloc` at `0x5c8b956` through `0x64e1570` when
old capacity is zero, otherwise `realloc` at `0x5c8b93a` through `0x64ec890`.
Its explicit output words are in the installer's stack scratch. On the
nonzero imported-return branch the tag is zero and the pointer-like return
is stored at output+8, which is the value subsequently installed at H+8.
Allocator internals, ownership, null returns and interposition remain open.

## Append interval and the field-preservation premises

On normal registration return, the two stores at `0x5ca0dbb` / `0x5ca0dbf`
append the supplied object pointer and callback in this interval:

```text
[B + 16*n, B + 16*n + 16)
```

Here B is reloaded after any growth, while n is the retained old count. Count
is then incremented and the guard is incremented. With successful growth,
`n=C` and `C+1 <= N`; without growth a valid append requires `n<C`. The binary
tests equality to select growth, not the stronger `n<C` condition. Corrupt
metadata with n>C is therefore not automatically rejected by that branch.

For the tracked word at `[P+0xc8,P+0xca)`, the explicit append interval is
disjoint iff it ends at/before P+0xc8 or starts at/after P+0xca. The worksheet
checks this relation, both adjacent boundaries, address wrap and malformed
count/capacity cases. Those checks define the admitted analysis conditions;
they are not newly implemented runtime checks in the node. Intersection
checks alone do not prove separate allocations or valid allocator ownership.

Consequently a field-preservation conclusion for this fallback still requires:

- T=F, valid TLS/list state, successful selected normal returns and adequate
  buffer capacity; the guard-zero and import-absent branches are selected.
- Separate stack, key global, TLS metadata and list-buffer storage from the
  tracked allocation, including valid old/new allocator ownership.
- Ordinary imported pthread/malloc/realloc behavior, no interposition that
  changes P, and no interfering concurrent/asynchronous write or callback.

No P pointer is explicitly supplied to these helpers on the joined path,
but that observation is not an alias or external-side-effect proof. The
normal fallback now has named imported boundaries and concrete local write
regions; it does not provide unconditional closure of the flag-other path.

## Reproduce, verification and remaining scope

With Python 3.12, Capstone 5.0.7, GNU objdump and llvm-objdump on PATH, from
the repository root and using fresh directories:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/tls-join.py --out work/context-tls-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/tls-join.py --out work/context-tls-optimized
```

The complete capture is authenticated first. Fresh native outputs retain
all 752 bytes and match Capstone partitions with documented LOCK-prefix joins;
versions and exact commands are in [tls/versions.json](tls/versions.json) and
[tls/commands.json](tls/commands.json). Normal and optimized outputs are
byte-identical. The two registration exports also match the previous poll
packet. Existing dependency native exports are validated against the target;
their older tool formatting is not required to equal this host's formatting.

All **59 new corruption/scope controls** reject their selected invalid input:
17 changed store bytes, two changed initial data words, 22 changed/duplicate
parsed relocations, five truncated FDEs, one missing store, three out-of-domain
capacities, seven interval/count cases and two wrong captures. Byte changes
may fail at body hashes before store pins. Scope/interval checks are arithmetic
over annotations, not target mutations or proof that excluded runtime states
cannot occur. The prior packet's original corruption tests remain separately
reported rather than relabeled as new controls.

Exact results and raw-log hashes are in [tls-validation.json](tls-validation.json).
The unchanged TLS suite retains its one Windows path-metadata failure;
catalogue checking retains the stale generated README failure. The prior
incomplete repository-wide suite in [validation.json](validation.json) is not
made green by the successful local adapter. No independent-agent review,
captured execution/emulation, Rust equivalence, hosted CI or container result
is claimed. All 92 gates stay false; no commit/push or network action occurred.

The next protocol-specific question is the accepted-state cleanup
`0x2a9dcd0` at outer call site `0x2ad5e3e`, which remains between copies in
the listener-to-factory chain. Scheduler invocation/lifetime, external TLS
contracts, large-A helpers and large B's origin remain separate gaps.
New work is independently authored MIT analysis; referenced evidence and
captured bytes retain their original rights.
