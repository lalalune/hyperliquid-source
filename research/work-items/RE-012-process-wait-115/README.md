# RE-012: node115 child wait cache, waitpid retry and pidfd fallback

Component foundation; task RE-012. Linux x86-64 node #115, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Coordinates are original ELF
virtual addresses, with no rebase or byte masks. New scripts/research are MIT.

## Question, gap and bounded result

After command creation, how does the actual node wait for its child, retain a
completed status, handle interrupted waits, and preserve errors through the
pidfd fallback? Prior command construction does not resolve this waiting
family. The public std census identifies the 304-byte Process::wait body, but
its dependency comparison does not explain the complete pidfd helper, ioctl
result/error policy, status dispatch or this node caller's status reads.

This static research closes those selected control-flow/data relationships.
It is not a new Rust implementation or a process simulator. The two primary
complete FDEs are `0x5c94a80..0x5c94bb0` (304 bytes) and
`0x5c875f0..0x5c877a4` (436 bytes). The full actual node caller
`0x1535fd0..0x153661e` (1,614 bytes) and tagged-error disposal
`0x5c74b90..0x5c74c5e` (206 bytes) are supporting context. Total retained
export denominator: **four FDEs, 2,560 bytes, 622 instructions**, 64 call and
92 branch records. Supporting windows were used before and earn no new
primitive/compiled-byte credit. All 92 full-scope gates and byte totals stay
unchanged. The dependency is public Rust std, not newly identified private code.

Live open PRs, unassigned issue inventory and recent merges were inspected on
2026-11-04. No competing process-wait/pidfd outcome was found. No issue was
opened, drafted or claimed. Main did not advance from the stated base.

## Process fields, output and cached fast path

At `0x5c94a80`, RDI is the output, RSI the process object. Relevant observed
fields are dword cached-status tag +0, dword cached raw status +4, dword pid +8
and dword pidfd +0xc. Only tag exactly 1 selects the cached path, before any
kernel call. That path copies the stored raw status to output+4 and stores
dword output tag 0. It does not close or poll the pidfd.

For a fresh wait, pidfd exactly -1 selects waitpid. Every other raw value
selects the pidfd helper with EDX=4. This observation does not assert that an
arbitrary negative fd or noncanonical process tag is a valid original Rust
value. On success, the waiter first stores process tag 1 and raw status +4,
then returns tag 0/status +4. On an error, it writes output tag 1 and the
64-bit encoded error at +8, without setting the process's cached status.
Unwritten output bytes are not normalized or counted as matching data.

The selected caller copies its process fields at `0x15362b5..0x15362e5`,
sets a separate descriptor field to -1, and calls this exact waiter at
`0x15362fa`. On a zero result tag it loads the raw status dword at
`0x15363b6`; after resource cleanup it tests the whole raw dword at
`0x1536403`, sending a nonzero value to the error-building branch at
`0x15364f5`. It does **not** decode just an exit-code byte at that reader.
The caller's command spawning, formatting/error construction, other cleanup
and returned application error contract remain separate work. This packet
binds a real caller, not a guessed application name or complete caller model.

## waitpid: only integer 4 retries

The local status dword is initialized to zero. The first imported call is
`waitpid(process.pid, &status, 0)`, through `0x64ec8a0`; it tests only whether
the result is -1. Every other returned integer proceeds to cache/store the
local status. No additional pid equality or status-kind check exists in this
body. This is a statement about actual code, not a claim a real blocking
kernel wait can return arbitrary integers.

On -1, slot `0x64dffc8` resolves to `__errno_location`. The errno dword is
zero-extended and packed as `(u64(u32(errno)) << 32) | 2`. Integer **4** is
the only retry discriminator. Its encoded immediate-error value is passed
to the retained tagged-error destructor, then the same pid, local status
pointer and options 0 are used again. The loop re-reads the retained errno
pointer after each -1. It does not re-zero status between attempts. Other
errors are returned immediately without committing a cache entry.

The selected tag-2 error's destructor path returns without heap disposal;
this is not a claim that every possible I/O error lacks owned storage. Raw
error encoding is observed locally; the complete public I/O-error ABI and
allocator effects are not recovered by this packet.

## pidfd waitid: present/none and code projection

The helper saves the fd from ESI, forwards EDX as options through ECX, zeros
128 local siginfo bytes, and invokes imported
`waitid(3, fd, &siginfo, options)` via `0x64ec820`. The current Process::wait
caller supplies options **4**, not a no-hang flag. No syscall was performed.

A return other than -1 reads siginfo dword +0x10. Zero returns result tag 0
and presence dword +4=0, leaving status +8 untouched. The caller regards this
none result as a nonreturn diagnostic boundary; it does not retry it or cache
zero. The actual call arguments and Source Location are retained.

For nonzero +0x10, siginfo code +8 is reduced by one and checked unsigned
against 5. Any other code reaches a separate diagnostic boundary. The actual
six-entry signed-relative table at **0x947e7c** maps codes 1..6 to complete
instruction boundaries. Its raw bytes and all targets are in `dispatch.json`.
The status source is the dword at siginfo+0x18.

| Raw code | Observed result at output+8 |
| --- | --- |
| 1 | `(u32(status) << 8) & 0xffff` |
| 2 | `u32(status)`, unchanged |
| 3 | `u32(status) \| 0x80`, without an added 16-bit mask |
| 4 or 5 | `((u32(status) << 8) \| 0x7f) & 0xffff` |
| 6 | `0xffff` |

Every present result stores output tag 0 and presence dword +4=1. These are
raw numeric/layout observations. They correspond to customary Linux child
status classes, but no host-platform wait macros, event generator, signal
send or invalid-input execution was used as a purported Linux oracle.

## Error 10 fallback: ioctl failure retains the original error

On waitid -1, the helper reads and packs errno using the same immediate-error
relation. **There is no integer-4 retry in this helper.** Any errno other
than **10** returns that encoded error directly.

Only errno 10 attempts imported ioctl `0x64e89d8` on the same fd, request
**0xc040ff0b**. Its 64-byte local input/output buffer has first qword **8**
and the remaining 56 bytes zero. The original waitid error is retained across
the call. This packet identifies the raw request/layout, without relying on
an unpinned host kernel header or asserting its availability on a deployment.

If ioctl returns anything other than -1, the helper copies the raw dword at
buffer+0x3c directly to status +8, stores tag 0/presence 1, and disposes the
old encoded waitid error. It does not apply the six-code siginfo transformation
to that already packed status.

If ioctl returns -1, the current errno is read, encoded and sent to error
disposal, while the **original waitid errno-10 error** is returned. Thus the
secondary ioctl error does not replace it. No fallback to waitpid or further
retry occurs in this selected pidfd failure branch. Cache writes still belong
to the caller's success path; neither failure commits a completed status.

## Identity, relocations and independently reproduced exports

`collect.py` reads the authenticated image, FDE/CIE/LSDA references, complete
instruction partitions, direct and indirect control flow, and encountered
relocation writers. GNU2.45 and LLVM23.1.4 objdump agree with Capstone5.0.7
on every byte of all four bodies; GNU readelf independently confirms extents.
There are no normalized operands. A standalone LLVM lock-prefix row, if
present, may only be joined to its immediately contiguous instruction; no
bytes are removed or replaced.

Five actual dynamic symbol writers are independently checked: **waitpid,
waitid, ioctl, __errno_location and close**. Four selected RELATIVE writers
bind the nonreturn diagnostic target, both Source Location paths, and the
shared deallocation context. The two Source Locations retain path lengths,
line/column layouts and exact files under compiler commit
`59807616e1fa2540724bfbac14d7976d7e4a3860`:
`library/std/src/sys/pal/unix/linux/pidfd.rs` and
`library/std/src/sys/process/unix/unix.rs`. Paths establish provenance, not
complete compiler flags, source-build equivalence or original ABI.

Diagnostic pointer/length arguments are recorded exactly as observed, including
pool spans of 169 and 171 bytes. Their pool prefixes identify the unreachable
conditions, but adjacent pooled text and opaque formatting/panic behavior are
not presented as an observed runtime message. Unwind references are retained;
LSDA action/catch behavior and the whole unwinder are not interpreted here.

## Reproduce and attack the retained evidence

From repository root, with the installed pinned Python/native tools:

```sh
source work/environment/new-three-env.sh
python3 -B research/work-items/RE-012-process-wait-115/collect.py --out work/fresh-process-wait
# records.json and all nine native exports must be byte-identical.
python3 -B research/work-items/RE-012-process-wait-115/verify.py --out work/fresh-process-wait-check.json
```

The verifier re-exports and compares every retained native file and record.
It then independently rejects **31 actual instruction-window mutations and
seven actual data/path/table mutations**, **four RELATIVE-addend mutations**,
**five imported-writer mutations**, and two wrong/truncated capture identities.
Narrow operand/data/writer checks do not rely on artifact hashing to detect
these corruption controls. Nothing executes a mutated captured instruction.
`qualification.json`, `scope.json`, `records.json`, `tools.json` and the
checksum manifest retain the exact result and identities.

During preparation two draft pin ends fell inside instructions. They were
widened to full instruction ends before final collection/qualification; the
body/data claims did not change. The discarded draft export and actual log
remain under ignored `work/environment/process-wait-task/`. No failed runtime
result or compiled comparison is omitted or relabelled as a pass.

Repository publication runs doctor/verify/catalogue-check/reproduce and the
13 relevant catalogue tests. The unchanged main-base 583-file qualification
(25 explicit skips) is reused and is not represented as a new full make test.
This changes evidence inventory only; no global tooling or production source
is edited. Generated inventory changes do not measure reconstructed bytes.

No captured node/visor, emulator or instruction evaluator was run. None of
the recovered process-launch, wait/close/ioctl/errno or other node operations
was executed; no node networking, chain or signing action occurred. No native runtime, ABI, hosted CI,
container or complete node equivalence is claimed. Kernel effects, concurrent
process access, noncanonical raw objects, full caller logic and panic/unwind
behavior remain boundaries. Next bind process creation's pid/pidfd/cache
initialization and exact ownership into this verified wait family.
