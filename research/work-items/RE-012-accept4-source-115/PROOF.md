# Node115 accept4 boundary and actual caller integration

The sole active target is Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105,896,032 bytes. All coordinates are original ELF virtual addresses with
exclusive ends. [static/records.json](static/records.json) binds fresh bytes,
full FDE/CIE records, complete GNU/LLVM exports, imports, tables and caller
instruction boundaries. This is a static normal-return proof, not captured
execution or an instruction emulator.

## Fresh target boundary and domain

The complete FDE `[0x475b050,0x475b154)` contains 260 bytes / 64 instructions.
RDI is the output pointer saved in RBX; RSI addresses a readable listener-fd
dword. At `0x475b05b` the helper writes 128 to the socklen dword at RSP+12.
It loads EDI from `[RSI]` and calls accept4 at `0x475b074` with
`(fd, RSP+16, RSP+12, 0x80800)`. Scratch address storage is not initialized.
The output pointer is not passed to accept4.

Three unique full-slot R_X86_64_GLOB_DAT writers resolve accept4 at
`0x64eb068`, `__errno_location` at `0x64dffc8`, and close at `0x64dfe78`.
The slot bytes, actual writer records and RIP-relative calls are authenticated.
Linux interface documentation supplies names and conventional flag meanings;
the captured instructions, not those conventions, establish the raw predicates.

The proof requires normal SysV import returns, a valid stack, readable listener
and errno storage, and every reached address byte initialized by the import.
Output, listener, scratch and errno regions are disjoint and stable except for
declared import effects. Imports do not reenter and alter output/control state.
The caller result image has 40 bytes: the helper writes at most through byte37,
and callers copy the untouched final two bytes too. Numeric output identity is
a full u64 observation; no native Rust enum layout is inferred from it.

No post-import socklen load occurs. A supplied length is therefore not a bounds
check, and missing initialized fields cannot be justified by a synthetic length.
Tests supply raw import results, families and volatile-register observations;
they do not assert that arbitrary probes are kernel outputs or valid public
Rust values. Faults, signals, unwinding, reentrancy and import implementations
are outside this normal-return contract. This helper's FDE has no LSDA.

## Complete helper relation

The `test eax,eax; js` at `0x475b07a..0x475b07e` rejects every negative i32,
not merely -1. It reads no address byte, requests errno once at `0x475b0a5`,
zero-extends the errno dword and constructs `(u32(errno)<<32)|2`. It writes
that qword at output+8, then result dword1 at output+0. Other output bytes
survive. This arm performs no close and restores the complete RBX pointer to
RAX at `0x475b0bf`.

For nonnegative EAX, `0x475b07e` loads the entire unsigned u16 family. It checks
10 first, then2. Thus `0x0102` and `0x010a` are unknown families. Family2 reads
scratch+4/4 as address bytes, scratch+2/2 as port and rotates the port by8 bits.
Family10 reads the port, flowinfo, scope and all16 IPv6 address bytes. The
shared publication sequence is exactly:

| Output offset / size | IPv4 | IPv6 |
| --- | --- | --- |
| +4 / 4 | nonnegative accepted fd | same |
| +8 / 2 | 0 | 1 |
| +10 / 4 | scratch[4..8] | zero, zero, scratch[8..10] |
| +14 / 2 | host-order port in little-endian bytes | scratch[10..12] |
| +16 / 8 | post-accept R11 | scratch[12..20] |
| +24 / 4 | post-accept R10D | scratch[20..24] |
| +28 / 4 | post-accept EDI | scratch[4..8], raw flowinfo |
| +32 / 4 | post-accept ESI | scratch[24..28], raw scope_id |
| +36 / 2 | 2 from the full family load into ECX | host-order port |
| +0 / 4, last | 0 | 0 |

IPv4 inactive bytes16..35 are overwritten from SysV caller-saved registers
whose post-import values are unspecified. They are neither preserved nor
justified zeroes or incoming argument values. The mathematical relation marks
them `??` unless four explicit post-import observations are supplied. Offset36
is inactive but determined as2; bytes38..39 remain unchanged.

For IPv6, the dword scratch+8 is shifted left16 within32 bits, introducing two
zero bytes at output+10..11. A separate word scratch+10 supplies the next two
bytes, so the complete16 address bytes occupy output+12..27 without reversal.
Flowinfo/scope are raw native dwords; only the port is swapped. The exact read
order is offsets0/2,2/2,4/4,24/4,8/4,10/2,12/8,20/4. Both success arms request
neither errno nor close, publish result0 last, and restore RAX at `0x475b120`.

For every other family, the code writes qword `0x1400000003` to output+8 at
`0x475b136`, then dword1 to output+0 at `0x475b13a`. Only afterward does it
request close(accepted_fd) at `0x475b142`. The return and any changed errno are
ignored, without retry. RAX is restored at `0x475b148`. Final-output stability
needs the import premise; publication before the call follows from the bytes.
This is one explicit close request, not a theorem about descriptor lifetime.
Every helper path is acyclic and ends in one of three returns.

## The four node115 callers

A whole-text E8 census validated at complete-FDE instruction starts finds four
sites. No RELATIVE slot contains this helper entry. This census and all full
bodies were extracted from node115, not moved from historical node94 addresses.

| Complete caller FDE | Bytes | Helper call | Output RSP+ | Registration / tag2 close |
| --- | ---: | --- | --- | --- |
| `0x2afae20..0x2afbc22` | 3586 | `0x2afb455` | 0x110 | `0x2afb526` / `0x2afb545` |
| `0x2cc02d0..0x2cc111b` | 3659 | `0x2cc0958` | 0x110 | `0x2cc0a29` / `0x2cc0a48` |
| `0x5a5e290..0x5a60a43` | 10163 | `0x5a5f9ac` | 0x290 | `0x5a5fa9d` / `0x5a5fabf` |
| `0x5cdfe50..0x5ce008a` | 570 | `0x5cdfefe` | 0x10 | `0x5cdffad` / `0x5cdffc6` |

The first three compare the result's low byte with0; the fourth compares its
dword with1. On the helper's actual0/1 results these agree. Each success path
copies fd and32 address bytes from helper output+8, including inactive bytes
and the two preserved tail bytes. Copying these does not define their logical
meaning. Each calls actual registration target `0x5cf24b0` with interest3.

Runtime lookup, registration, diagnostic construction, cleanup, drop and later
readiness machinery remain explicit opaque boundaries. On full registration
tag2, the fd passed to close is reloaded from its temporary slot afterward.
The relation exposes the post-registration value; it does not assume the
callback preserved the accepted fd. Raw tags are u64 and reloaded fd slots
are dwords; opaque callback success conventions beyond the observed tag test
are not invented.

The first three then test the saved address tag's low bit at `0x2afb594`,
`0x2cc0a9a`, `0x5a5fb16`. For actual tags0/1 this rejects IPv6 after
registration. Their authenticated nine-byte `ip not v4` literals reside at
`0x606ec3`, `0x60f89e`, `0x93c599`. They construct a diagnostic, call cleanup
at `0x2afb5b7`, `0x2cc0abd`, `0x5a5fb39`, reload the aggregate fd and call
close at `0x2afb5c5`, `0x2cc0acb`, `0x5a5fb47` only if the reloaded i32 is
not -1, then request drop. The post-cleanup value is explicit in the relation;
no global exactly-once cleanup claim crosses these opaque boundaries.
IPv4 continues at `0x2afb779`, `0x2cc0c6d`, `0x5a602c7`.

The fourth has no such family gate on its post-registration success path.
`0x5cdfff6..0x5ce0028` forwards the32 address bytes to caller output+32,
alongside registration values and the reloaded fd. This proves a local
forwarding boundary, not a complete async poll routine or whole caller.

## Node115 error classification

The first three dispatch low-two-bit error tags through four-entry signed
relative tables at `0x6043fc`, `0x60bce8`, `0x939504`. Every target is a decoded
instruction start and no relocation writer overlaps these table bytes. For
helper-generated tag2, only the full high dword11 takes the would-block
boundary. For tag3, node115 clamps that high u32 to42 before comparing its
low byte with13. The helper emits20, so unknown-family conversion never takes
the would-block arm. Custom-pointer tags are unreachable from this helper.

The fourth calls complete classifier `[0x5cdf1b0,0x5cdf270)`, 192 bytes /
99 instructions. Its four-entry table `0x94c7a4` and122-entry table `0x94c7b4`
are fully bound. Packed errno computes `(u32(errno)-1)` and indexes only if
the unsigned result is at most121. Exactly entry10 returns AL13 at
`0x5cdf243`; only errno11 is would-block. Default AL is41. The simple-tag arm
at `0x5cdf1ec` clamps the high u32 to42, so fixed20 returns20. Only AL is
consumed; the complete supporting function's RAX is not claimed.

The four would-block boundaries are `0x2afb5ea`, `0x2cc0af0`, `0x5a5fb6c`,
`0x5cdff1f`. Other helper errors reach the respective error handoffs without
new registration or a local second close of the accepted fd. CAS progress,
retry termination, later future polls and opaque callbacks remain unproved.

## Historical migration and licensed source countercheck

[migration-boundary.json](migration-boundary.json) authenticates both complete
captured helper bodies. All differences are inside the three four-byte call
displacements, whose old/new dynamic import names are separately bound. Nine
bytes differ; masking the twelve operand bytes leaves the other248 identical.
This is a historical migration observation, not a source-built comparison or
new byte credit. Caller count changes from5 to4, and the error classifier grows
from180 to192 bytes with the new unsigned simple-tag clamp. These differences
are why historical callers/layouts cannot be relabeled as node115 proof.

The licensed Mio1.0.2 Unix source and its previously published original/repeat
Linux objects are authenticated through [source-provenance.json](source-provenance.json).
The complete object SHA is
`0e87b268ec70b19818b391b69ef1bdeb314d6837219ff5706d732fa5c4062b78`.
The complete `TcpListener::accept` FUNC and corresponding PC32 FDE contain
239 bytes /61 instructions with three actual GOTPCREL import records. The
source creates an owned stream after accept and drops it if address conversion
fails. It corresponds to the active logical-address behavior, but does not
prove original crate/version, layout or build provenance.

The new whole-target comparison is260 versus239 bytes, unmatched without
normalization, truncation or padding. Source close+0xc8 precedes error stores
+0xd8/+0xe1; node115 publishes its error first. Full raw output/event identity
is therefore disproved for this source build. The one Mio candidate is
registered as an unequal-extent dependency comparison, with no aligned-byte
credit or component gate change. This packet reuses and reauthenticates the
existing build; it does not claim new compilation or independent replication.
No Mio version string was found by the bounded package-version regex in this
capture, and neighboring public source correspondence is not unique attribution.
