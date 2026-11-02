# Node94 keepalive dependency and caller contract

Target: Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Addresses below are linked ELF virtual addresses before load bias.

The complete helpers are `[0x4ecd970,0x4ecda53)` and
`[0x4ecda60,0x4ecdb43)`: 227 bytes and 60 instructions each. Their only
callees are named `setsockopt` and `__errno_location` imports. The complete
caller FDEs `[0x29aeb40,0x29af8ce)` and `[0x29c3300,0x29c4108)` are retained
as context. The claim about callers covers their keepalive configuration,
error treatment and continuation boundaries, not all 7,062 caller bytes.

## Complete helper relation

Let `P` be the incoming RSI record address, `fd` the low 32 bits of RDI,
`S = 1,000,000,000` and `M = 2,147,483,647`. All memory quantities below
are little endian. The only record reads lie in `[P,P+36)`:

| Admission predicate | Value | Request `(level, option, bytes, length)` |
| --- | --- | --- |
| `u32(P+16) != S` | `min(u64(P+8), M)` | `(6,4,LE32(value),4)` |
| `u32(P+32) != S` | `min(u64(P+24), M)` | `(6,5,LE32(value),4)` |
| `u32(P) == 1` | `u32(P+4)` | `(6,6,LE32(value),4)` |

These requests execute in table order, with the same `fd`. Each value lives
in a separate four-byte stack temporary, passed by address to `setsockopt`.
The helper does not enable `SO_KEEPALIVE`; its callers do that first.

A request fails precisely when its 32-bit return equals `0xffffffff`.
Other negative raw returns are not failures at this boundary. On the first
failure the helper skips later record predicates and calls
`__errno_location`, reads its pointed-to u32, and returns
`RAX = (u64(errno_word) << 32) | 2`. Earlier successful option effects remain.
If no request fails, full RAX is zero. The helpers neither close a descriptor
nor allocate or write a caller-owned result record. They preserve their
callee-saved RBX/R14 and restore the stack. No other caller-saved register is
promised as an output.

The two unsigned `CMP`/`CMOVB` pairs prove the clamp for every u64 value,
including values above `i64::MAX`. Retry values are copied without this
clamp. The exact dword tag comparison differs from a low-bit test. The fixed
three-stage graph has no loops: each admitted request either ends the function
or advances to the next stage, proving termination under normal imports.

This raw relation includes artificial values outside valid Rust
`Option<Duration>`/`Option<u32>` representations. In particular a nanosecond
word other than S is treated as present even above the valid nanosecond range,
and a retry tag 3 is absent. It does not assert those values arise from the
public socket2 API. Native libc normally returns 0 or -1; -2 probes distinguish
the captured predicate without claiming operating-system reachability.

## Accepted-connection caller stage

The first caller invokes helper `0x4ecd970` at `0x29af13a`. Its relevant
configuration is based at R14:

- retry tag/value: dwords `+0x20/+0x24`;
- time seconds/nanoseconds: qword `+0x28`, dword `+0x30`;
- interval seconds/nanoseconds: qword `+0x38`, dword `+0x40`.

At `0x29af096..0x29af0be` the stage is skipped only if both nanosecond
words equal S and bit 0 of the retry tag is zero. If entered, the temporary
retry tag is the original low bit. Thus caller tag 3 becomes helper tag 1;
it must not be conflated with passing raw tag 3 directly to the helper.
The time-seconds field is loaded only when time is present. A stale R8 value
may be stored into the inactive temporary time field; this packet does not
invent its value or claim that every temporary byte is initialized.

The fd at `[RSP+0x40]` is checked before enabling keepalive. -1 reaches
`0x29af580`; another negative value reaches `0x29af69d`. The latter path
uses the actual `socket2-0.5.7/src/sockref.rs:89:9` Location at `0x56cc100`.
These panic paths are outside the normal stage relation.

On the admitted fd path, `0x29af121` calls
`setsockopt(fd,1,9,&LE32(1),4)`. Only return -1 skips the helper and obtains
errno at `0x29af20f`. Otherwise the helper is invoked. Both nonzero helper
results and enable errors publish the error word into the stack slot
`[RSP+0x68]`, then enter the conditional tracing path. No abstract "success"
result is invented for tracing: its actual callees remain opaque.

Assuming tracing returns normally without changing its borrowed error word,
`0x29af304` reloads that same error word and
checks `(word & 3) == 1` at `0x29af30e`. Every error from this closed keepalive
path has low bits 2, so the custom-error drop arm `0x29af512` is unreachable.
The caller continues at `0x29af317`, where the next TCP_NODELAY setup starts.
The same continuation is reached when keepalive was skipped or succeeded.
There is no explicit descriptor close on these keepalive-error paths before
that continuation. This does not describe later failures or tracing unwind.

The initial tracing cell `0x577ccf0` has a RELATIVE pointer to metadata
`0x56ca728`. Its file pointer/length at `+0x60/+0x68` names
`hyper-0.14.29/src/server/tcp.rs`, and its line is 217. Public licensed Hyper
0.14.29 source at lines 214–221 independently has the optional socket2
configuration, trace-on-error, then TCP_NODELAY sequence. Initial relocations
are not asserted to be immutable live runtime cells.

## Client configuration stage

The second caller invokes helper `0x4ecda60` at `0x29c3403`. The duration
nanoseconds at `[R13+0x68]` gates the stage; S skips directly to `0x29c360c`.
Otherwise seconds at `+0x60` and those nanoseconds form a temporary record
at `[RSP+0x88]`; retry tag is 0 and interval nanoseconds is S. The inactive
retry/interval words are not consumed by the helper.

At `0x29c33ea`, `setsockopt(fd,1,9,&LE32(1),4)` precedes the helper.
Return -1 obtains errno at `0x29c3505`; a helper error joins at
`0x29c3515`. The error word is stored in `[RSP+0x60]` and reaches the
conditional tracing path. On normal return, with the borrowed error word unchanged, it is reloaded at
`0x29c35f9`.
The low-two-bit check at `0x29c3603` cannot select custom-error drop
`0x29c36ca` for these packed errors. The caller continues at `0x29c360c`
into address-dependent setup. Keepalive failure therefore does not itself
return a connect error or close this fd.

This FDE also contains a directly used `socket2-0.4.10/src/socket.rs:105:17`
Location at `0x5751a48`, on its earlier invalid-socket path. The keepalive
tracing cell `0x577d5c0` initially points to metadata `0x56ce898`, whose
file field names `/home/ubuntu/hl/hyper-fork/src/client/connect/http.rs`
and line 648. Public Hyper 0.14.29 client source has a comparable
warning-and-continue block at lines 614–619, but it is not the private fork.
Neither neighboring strings nor that public similarity recover private
patches, exact crate identity, or the rest of the client.

## Domain and limits

The proof assumes stable readable input fields and ordinary nonaliasing stack
storage, correctly resolved libc import slots, valid four-byte errno storage,
and normal synchronous import/logging returns. The opaque logging/formatting
callbacks must leave their borrowed error word unchanged; normal return alone
is not a proof of that property. This explicit premise is needed because both
callers reload the stack error word after logging. Reentrant callbacks, signals
mutating input, forged descriptor ownership, exception/unwind behavior and
allocation failure inside logging are not modeled. No claim about an entire
async caller, accepted connection, successful connect or live network follows.

The static check binds all four FDEs and complete bytes, complete helper import
closure, the two direct callers, source Locations and initial tracing records.
Caller context exports include code that remains semantically unclosed.
The separate finite protocol model is a mathematical counterexample aid, not
an instruction emulator, native target oracle or replacement socket runtime.
The public-source build compares complete symbols and retains negative results;
its passing build/tests do not establish target behavior or whole-node identity.
