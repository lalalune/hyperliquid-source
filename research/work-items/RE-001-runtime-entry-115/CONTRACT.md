# Node115 runtime entry and initialization boundary

This is a static relation for the sole implementation target, Linux x86-64
node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
It closes the previously unvalidated link from the ELF entry to the Rust main
wrapper, actual callback vtable, selected runtime setup and normal-return exit
guard. Linked virtual addresses below are not file offsets or loaded addresses.

The six complete FDEs contain 1,857 bytes and 434 decoded instructions. Five
primary bodies account for 1,819 bytes; the existing 38-byte ELF entry is context.
All code, cold tails, CIE/FDE records, selected LSDA intervals, RIP operands and
actual relocation writers are retained. An FDE supplies an unwind extent;
complete decoding and local branch-boundary checks are additional evidence.
No captured code, emulator, libc call, signal installation or live node ran.

## Main and actual callback

The ELF header names `0x1419300`. Its LEA at `0x1419318` passes
`0x2cef8f0` to the actual `__libc_start_main` slot `0x64df458`.
The wrapper `[0x2cef8f0,0x2cef917)` sign-extends EDI into RDX (argc), copies
RSI to RCX (argv), and stores callback `0x2cd8370` in its stack slot.
It passes that slot in RDI, vtable `0x6440b48` in RSI, and zero in R8D.
The call at `0x2cef90f` uses slot `0x64e6c30`, whose unique RELATIVE writer
names the complete runtime `[0x5c99970,0x5c9a045)`.

The vtable header is `[drop=0,size=8,align=8]`. Its three actual RELATIVE
method slots at +24/+32/+40 name `0x292e230`, `0x292c5c0`, and `0x292c5c0`.
Each 13-byte adapter loads the callback pointer from RDI, invokes the complete
five-byte `0x2c7bb70` adapter (`call rdi`), and explicitly clears EAX afterward.
The runtime's call at `0x5c99e21` uses vtable +40. Therefore, under ordinary
returns through these exact adapters, the selected callback's return registers
do not become a CLI/process exit status: the adapter supplies i32 zero.
The private callback body is excluded. This is not a claim that all program
terminations return zero; explicit exit, panic and nonreturning calls remain.

This relation requires the established ABI, valid disjoint stack/vtable memory,
ordinary imported-function contracts and preservation of live values by opaque
callees. It does not admit arbitrary pointer aliases, MMIO, asynchronous mutation,
corrupt process state, arbitrary throwing imports or entry into interior bytes.
No safe Rust replacement or ABI compatibility claim is made.

## Runtime setup

The first block reads thread-local qword FS:-0x420. If zero, it increments the
counter at `0x6500050` using LOCK CMPXCHG, retrying on interference. An observed
counter of u64::MAX enters `0x5ca4480`, an unresolved failure helper. On success
it stores the chosen ID in TLS and `0x64fffe8`. These globals lie in the actual
writable PT_LOAD zero tail `[0x64ffe08,0x6728924)`; this is loader initialization,
not a claim that runtime values remain zero. The x86 instructions alone do not
identify the source-language atomic ordering or prove global liveness.

Standard descriptor sanitization constructs three eight-byte pollfd records for
FDs 0, 1 and 2 with events/revents initially zero. The 16-byte literal at
`0x453950` provides records 1 and 2. R14 reaches the `poll` slot `0x64e2320` and
R15 initially reaches `__errno_location` at `0x64dffc8`. The call at `0x5c99a1a`
requests nfds=3 and timeout=0. Only EAX==-1 enters error handling. Errno 4 retries;
unsigned errno <=22 with a set bit in 0x401800, exactly {11,12,22}, uses the
fcntl fallback. Other poll errors enter the imported abort call at `0x5c99bb8`.

For a non-(-1) poll return, the loop tests each revents byte's 0x20 bit and
repairs selected entries. In the fallback it calls `fcntl(fd,1)` for each of
0/1/2 and repairs only return -1 with errno 9. Repair requests `open64` of the
NUL-terminated `/dev/null` at `0x44fa5e`, flags=2 and mode=0. If an earlier open
succeeded, it first tries `dup` of that descriptor; exact return -1 falls back
to open. Exact open return -1 reaches abort. There is no close in this repair
sequence. The ordinary Linux import interpretation is supported by the pinned
Unix runtime source. Actual repair success additionally requires ordinary FD
allocation and no interfering descriptor-table changes; the static request
sequence alone does not establish a runtime postcondition for arbitrary races.

The raw low byte of R8 selects a signed four-entry table at `0x9486e8`:

| Value | Destination | Request | Explicit-setting byte `0x64ffffc` |
| --- | --- | --- | --- |
| 0 | 0x5c99bc7 | signal(13,1) | not written here |
| 1 | 0x5c99b4b | no signal call | 1 |
| 2 | 0x5c99bc0 | signal(13,1) | 1 |
| 3 | 0x5c99bbe | signal(13,0) | 1 |

Values above 3 reach the diagnostic boundary at `0x5c99f24`. The exact actual
main supplies zero; it selects SIGPIPE ignore while leaving the explicit-setting
flag unchanged. The `signal` import is `0x64ec808`; RAX==-1 enters a diagnostic
path, not the continuation. The official compiler constants corroborate this
mapping. No other process's signal state was inspected or changed.

At `0x5c99be1`, sysconf receives 30; its returned qword is stored and reloaded as
the page-size operand. pthread_self and pthread_getattr_np follow. Nonzero
getattr return skips the guard arithmetic. On zero, pthread_attr_getstack and
pthread_attr_destroy must each return zero to continue; errors enter diagnostic
helpers. The raw stack base is rounded upward by its remainder modulo the page
operand, then one page is subtracted to form the lower bound. Page zero takes
an explicit diagnostic branch. There are 32-bit and 64-bit DIV arms selected by
whether both operands fit 32 bits. Pointer reachability, page-size validity and
wraparound exclusion require the ordinary OS premises; they are not derived
from the source label. Node115 uses EBX for the getattr result and R14 for the
lower bound. Historical register assignments are not reused.

The runtime queries sigaction for signals 11 then 7. It tests the resulting
handler qword and requests installation only when it is zero. The installed
record uses flags 0x08000004 and handler `0x5ca4100`. Calls to `0x5ca3e50` and
`0x5ca2950` provide conditional alternate-stack/guard setup, but their whole
behavior remains outside this packet. Every sigaction return is unchecked.
Consequently a failed query can leave the initially zero or subsequently reused
buffer contents in place; this packet does not assert successful queries or
successful handler installation. Actual signal delivery is also excluded.

## Arguments, cleanup and exit guard

The saved argc/argv are written to `0x6500000`/`0x6500008` immediately before
the callback. After the callback, EAX is sign-extended into RBX. The runtime reads
cleanup state `0x64fed90`; its file image is dword 3, distinct from the BSS
globals above. If the observed state is nonzero, it invokes the actual RELATIVE
slot `0x64df9f0 → 0x5c87d50` with its local callback environment and returns to
the exit guard when that call returns. The once implementation, its callback's
full I/O/cleanup effect and every cleanup callee remain boundaries.

The exit guard calls __errno_location, then uses its returned pointer as the
new value in LOCK CMPXCHG at `0x6500078`, expected value zero. Successful CAS
returns the saved result. On failure, equality with that same pointer enters
the reentrant diagnostic at `0x5c99ee4`; a different pointer reaches the `pause`
slot `0x64ec900` and loops after each ordinary return. This function does not
itself call libc exit. Source-language Acquire/Relaxed attribution, thread
identity lifetime, global shutdown safety and termination are not proved from
this local instruction sequence.

The LSDA at `0x3ff828` binds the callback interval
`[0x5c99e19,0x5c99e24)` to landing pad `0x5c99f54`, action index 5. The cold code
contains EBX=101 and payload-disposal calls. The full body and eight call-site
rows remain available, including action indices 3/5. Their action/type-table
closure, unwinder personality and all nested destruction are not reconstructed.
Neither “all panics return 101” nor total exception safety is claimed.

## Source correspondence, migration and limits

The exact pinned official Rust source is commit
`59807616e1fa2540724bfbac14d7976d7e4a3860` (1.95.0), with MIT/Apache notices and
full public files retained in the source archive. The target .comment contains
`rustc version 1.95.0 (59807616e 2026-04-14)`. This string is an observed label,
not an authenticated original build recipe. Public rt.rs, Unix initialization,
stack-overflow setup, compiler SIGPIPE constants and sys/exit.rs corroborate the
selected order and purposes above. No source was built or compiled window
compared in this packet, so no byte-registry row or compiled-code credit is due.

The historical #94 exploration was stopped when policy c3b77a8e made #115 the
sole target. It was used only as a search lead. All current bodies, entry fields,
imports, vtable writers, jump-table words, globals and exception intervals were
read from the authenticated #115 image and freshly exported through GNU/LLVM.
Concrete drift includes FS:-0x420 (historical -0x448), saved-argument stack
slots, pthread result/guard registers, method addresses and LSDA intervals.
Equal runtime byte lengths alone would not validate the migration.

The four reconstruction gates remain false. Full private main/CLI behavior,
allocator and cleanup closure, signal/unwind behavior, exact toolchain/library
patches and a reproducible source-built executable remain unresolved. The next
integration boundary is the actual private callback `0x2cd8370`, whose internal
startup/configuration path must be established independently.
