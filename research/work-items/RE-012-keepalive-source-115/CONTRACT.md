# Node115 keepalive calls and error ownership

All current addresses are linked Linux x86-64 ELF virtual addresses in node115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The six complete FDEs cover 6,972 bytes and 1,444 instructions. Only the two
227-byte helpers and their callers' bounded keepalive stages are interpreted;
caller context and unreachable custom-error arms are not whole-function recovery.

## Helper protocol

The complete entries are `[0x5c68520,0x5c68603)` and
`[0x5c68610,0x5c686f3)`. Each has60 instructions and no LSDA. Input RSI points
to a stable36-byte read projection; RDI contributes its low32 descriptor bits.
This is an observed private machine boundary, not a stable Rust layout/API.
Little-endian fields select the following requests in this exact order:

| Predicate | Four-byte value | level/option/length |
| --- | --- | --- |
| u32 at+16 differs from1,000,000,000 | min(u64 at+8,2,147,483,647) | 6/4/4 |
| u32 at+32 differs from1,000,000,000 | min(u64 at+24,2,147,483,647) | 6/5/4 |
| full u32 at+0 equals1 | raw u32 at+4 | 6/6/4 |

The two CMP/CMOVB sequences are unsigned, including all high-bit seconds.
Retry values are not clamped. Both duration sentinels and the retry-tag equality
are exact; invalid raw nanosecond values and tags are artificial boundary probes,
not assumed valid Rust Option values. Each active request passes a separate
four-byte stack temporary and the same fd to `setsockopt` at GLOB_DAT
`0x64e1410`. No SO_KEEPALIVE enable request occurs inside these helpers.

A request fails only if its low32 return is exactly0xffffffff. In the stated
signed-i32 observation domain, -2 and INT32_MIN therefore continue. A first
failure skips all later predicates and requests, calls `__errno_location`
through GLOB_DAT `0x64dffc8`, reads its u32 once and returns full
`RAX=(u64(errno)<<32)|2`. No failure returns full RAX=0. Success, including no
requests, clears EAX and hence returns full RAX=0. Stack and callee-saved RBX/R14
are restored; no other caller-saved result is claimed. These bodies do not
allocate, close, retry, or write caller-owned result storage. The acyclic
three-stage graph terminates provided reached imports return normally.

## Actual accepted-connection stage

The complete caller `[0x2e6ba40,0x2e6c57d)` is2,877 bytes. Its helper call is
`0x2e6bff2`. Configuration R14 retains retry tag/value at+0x20/+0x24,
time seconds/nanoseconds at+0x28/+0x30 and interval at+0x38/+0x40.
At `0x2e6bf49..0x2e6bf74`, both duration sentinels plus a clear retry low bit
skip directly to `0x2e6c030`. Otherwise the temporary tag is tag&1. Raw caller
tag3 can therefore select retries while direct helper tag3 cannot. Time seconds
are loaded only on the present-time branch; the inactive temporary may receive
stale R8. No fabricated initialization of that field is assumed.

The fd is reloaded from RSP+0x30. -1 reaches `0x2e6c478`; other negative values
reach `0x2e6c4a2`. Those error boundaries are excluded from the successful
configuration stage. The latter uses actual Location `0x6458ff8`, naming
`z_vendor/socket2-0.5.7/src/sockref.rs`,89:9. The full captured path is retained.
Only then does `0x2e6bfdd` enable `(SOL_SOCKET=1,SO_KEEPALIVE=9,LE32(1),4)`.
Exactly -1 skips the helper and obtains errno at `0x2e6bffe`; another raw return
calls the helper. Any packed error is published at RSP+0x68 at `0x2e6c00e`.

The caller loads the mutable level pointer through `0x64df748`; nonzero level
skips tracing. At level0, the tracing interest byte at `0x64f2540` chooses
between enabled checking, registration, or bypass. Nonzero logging metadata
field+0x38 is required for the emission path; its missing-field error call is
not assumed to return successfully. The emission call is `0x2e6c264` to opaque
`0x5d004c0`. Every normal logging/bypass path rejoins `0x2e6c026`, reloads the
borrowed error word and calls outlined drop `0x2e6b0c0` at `0x2e6c02b`.
Then `0x2e6c030` begins the separate TCP_NODELAY request sequence. There is no
explicit close or returned socket error on this keepalive-error segment.

## Actual client stage

The complete caller `[0x2e7db50,0x2e7e7ed)` is3,229 bytes; its helper call is
`0x2e7dc70`. After the separate socket/fcntl boundaries, R12+0x68 nanoseconds
equal to the sentinel skip to `0x2e7de9f`. Present time reads seconds+0x60.
The temporary record at RSP+0x80 has retry tag0 and interval sentinel; its
inactive values are not consumed by the helper.

`0x2e7dc57` enables SO_KEEPALIVE before the helper. Exactly -1 obtains errno
at `0x2e7dd72`; helper failure and enable failure join at `0x2e7dd82`, storing
the error at RSP+0x50. The mutable level comparison is **unsigned >3**, unlike
the server's nonzero gate. Interest byte `0x64f2d50` then controls tracing.
The emission call at `0x2e7de86` also targets `0x5d004c0`. All normal paths
reload the error at `0x2e7de95` and call outlined drop `0x2e7bdd0` at
`0x2e7de9a`. `0x2e7de9f` continues address-dependent configuration. Earlier
socket/fcntl failures and later option/bind/connect failures are separate
paths: no claim that every error in this caller is best effort is made.

Its invalid-socket Location `0x64c2ad0` names
`z_vendor/socket2-0.4.10/src/socket.rs`,105:17. This contextual filename does
not establish an unmodified crate, an exact source version for the helper, or
an original dependency lockfile.

## New outlined error-drop boundary

The two complete206-byte FDEs `[0x2e6b0c0,0x2e6b18e)` and
`[0x2e7bdd0,0x2e7be9e)` differ in relocation operands. They mask low32 EDI
with3; `(tag-2) mod2^32 <2` returns for tags2/3. Tag0 also returns. Only tag1
proceeds to pointee reads, an optional dynamic destructor and allocation
cleanup. For every keepalive-generated `(errno<<32)|2`, the reached prefix
returns before any input-pointee read or callee. Thus no custom-error allocation
or socket descriptor is freed on this admitted path. Full other-tag ownership,
unwind actions and callbacks remain outside the claim despite retaining their
complete code as context. The drop return registers are not used or invented.

Both callers reload after logging. The proof therefore explicitly requires
normal logging returns **and preservation of the borrowed error word**.
Normal return alone does not prove that property. A callback changing lowtag2
to1 would enter the unclosed custom-error arm; the counterexample is retained.
The complete callees and their effect systems have not been reconstructed.

## Initial data and attribution

Slot `0x64df748` has a unique RELATIVE writer to file-backed word `0x64fee60`,
whose initial value is5. Runtime constancy is not claimed. Initial tracing
cells `0x64f2530`/`0x64f2d40` point to metadata `0x6456948`/`0x645a518`.
Their file fields name `z_vendor/hyper/src/server/tcp.rs` line217 and
`z_forks/hyper-fork/src/client/connect/http.rs` line648. Corresponding actual
Locations at `0x6456b28`/`0x645a590` are also bound. The server's new path is
unversioned; the historical Hyper0.14.29 label must not be transferred.

Official licensed Hyper0.14.29 is only structural corroboration of a
trace/warning-and-continue sequence. Its source is not the private fork.
Official socket2 0.4.10/0.5.7 source experiments are explicitly alternative,
nonmatching candidates. Current whole-source comparisons reuse authenticated
historical Rust1.94.1 objects; they do not rebuild source or establish the
original toolchain. The target rustc1.95.0 comment is an observation, not an
original compiler attestation. Neither a source-path string nor a matching
mathematical relation is binary equivalence.

Readable stable ordinary storage, valid errno pointers, normal synchronous
imports, nonaliasing stack/control memory and the stated logging premise are
required. Signal/reentrant mutation, invalid Rust objects, faults, unwinding,
opaque logging failures and complete async/network behavior remain unclosed.
No captured instructions, emulator, reconstructed networking shim or live
socket experiment is used. Full component gates remain false.
