# Node94 listener construction: ordinary import protocol

Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `e5c9b6436876b2a4a39daef813171f9879317699`.
The selected complete FDE is `[0x3cd6690,0x3cd67c1)`: 305 bytes and 81
instructions. Addresses below are linked ELF VAs. The existing
`transport-socket-calls-94` packet establishes socket arguments and the
NodePort call chain. This proof extends that boundary to exact address bytes,
ordinary call order, error publication, descriptor cleanup and return identity.
It does not assign first-party ownership or a dependency version. The accompanying public-source comparison is candidate-specific; no unlicensed reference source
was read or copied to formulate this relation.

## Domain and observable boundary

The original input pointer is saved in R14 and the output pointer in RBX.
For the complete byte relation, consider 32 stable input bytes, 16 initially
arbitrary output bytes, and ordinary signed-i32 outcomes for socket,
setsockopt, bind and listen. On a reached failure path, errno supplies the
four bytes read from `__errno_location()`. Close has an ordinary outcome
which the target ignores. No successful OS operation or
reachability of artificial outcomes is asserted.

Correspondence assumes valid stack/return state, ordinarily returning imports
which preserve SysV callee-saved registers, stable input bytes across calls,
valid reached output/errno accesses, and no reentry or concurrent mutation.
The bind callee observes only its supplied byte length. Actual libc/kernel
behavior, networking, exceptions, cancellation and resource lifetime beyond
this function remain outside the relation.

The expected return is pointer identity: full RAX equals the original output
pointer. It is not the descriptor, status or errno. This does not specify an original Rust ABI. Other caller-saved registers after imports are not
assigned values by this proof.

## Argument and address relation

Let `t = input[0] + 256*input[1]`. `MOVZX R15D,word [RSI]` reads the complete
u16. Socket is called at `0x3cd66b3` through `0x5775210` with:

```
socket(domain = 8*t + 2, type = 0x80801, protocol = 0)
```

The maximum domain is 524282, so the u32 LEA result does not overflow. The
type contains the captured Linux stream/nonblocking/close-on-exec bits; no
crate identity follows from those constants. A nonnegative low32 socket result
is saved as EBP. Then `0x3cd66de` calls `0x576f0d0`:

```
setsockopt(fd, level=1, option=2, value bytes=01 00 00 00, length=4)
```

Only after that succeeds does `TEST R15B,R15B` choose the address layout.
The test uses the low byte, not the full u16 tag and not a boolean conversion
for socket-domain formation. Thus artificial tag 256 requests domain 2050
but builds the IPv4 layout. Tag 257 requests 2058 and builds IPv6. These raw
inputs expose the boundary's actual widths; they are not asserted valid values
of an original Rust enum. Tags 0 and 1 supply the conventional two-family cases.

For `input[0] == 0`, the exact 16 bytes passed to bind are:

| Output sockaddr offsets | Bytes |
| --- | --- |
| 0..2 | `02 00` |
| 2..4 | `input[7], input[6]` |
| 4..8 | `input[2:6]` unchanged |
| 8..16 | eight zero bytes |

For `input[0] != 0`, the exact 28 bytes passed are:

| Output sockaddr offsets | Bytes |
| --- | --- |
| 0..2 | `0a 00` |
| 2..4 | `input[29], input[28]` |
| 4..8 | `input[20:24]` unchanged |
| 8..24 | `input[4:20]` unchanged |
| 24..28 | `input[24:28]` unchanged |

The port uses an AX rotate by eight; no corresponding byte reversal is
performed on the other fields. IPv4 reads the port at +6 then dword at +2.
IPv6 reads port +28, sixteen bytes +4, dword +24, then dword +20. Gaps/padding
not read by these instructions are not initialized or interpreted by the proof.

On IPv4 the target also stores caller-saved ECX at temporary sockaddr +24.
Its value is unknown after setsockopt, and that store is outside bind's 16-byte
observation. The temporary's complete 28 bytes are therefore not a defined
IPv4 payload. XMM0 is zeroed in that arm; its first eight bytes supply the
observed zero tail. No value outside bind's supplied span is compared.

Bind at `0x3cd676b` through `0x5775220` receives the saved fd and exactly
16 or 28 bytes above. After success, listen at `0x3cd677c` through
`0x5776450` receives that same fd and backlog 1024. The neighboring helper's
backlog 128 does not apply here.

## All status paths, storage and cleanup

Each of the four import results uses `TEST EAX,EAX; JS`, at `0x3cd66b9`,
`0x3cd66e4`, `0x3cd6771` and `0x3cd6782`. Consequently *any negative i32*
fails, not only -1. Zero and positive callback results proceed. The earliest
negative result ends the request prefix; no later construction call runs.

On socket failure, the target calls `__errno_location` at `0x3cd6712` and
reads its dword. It writes the error result and exits without close. On a
later failure it calls the same import at `0x3cd6791`, writes the same error
result, and calls close exactly once at `0x3cd67ad`. Both errno sites use
slot `0x576e8d8`; close uses `0x576e708`.

For raw errno bits `e`, the output word is `(u64(e)<<32)|2`. The dword load
into EAX zero-extends before shifting. A negative signed errno input is thus
preserved as its u32 bits, rather than sign-extending into low bits.

| Path | Ordered output stores | Bytes preserved |
| --- | --- | --- |
| Success | u32 fd at +4, then u32 0 at +0 | +8..16 |
| Any failure | u64 error at +8, then u32 1 at +0 | +4..8 |

Post-socket failure publishes both stores **before close**. Close cannot replace
the saved error and its return value is ignored. An observer at close must
therefore see the final error output including the original inactive +4..8
bytes. Socket failure has no such event. Normal return at `0x3cd67b3` always
copies RBX to full RAX and restores the saved registers/stack.

Only the tag is read before socket/reuseaddr results. The rest of the address
is reached only when both succeed. Original minimal accessed input extents are
two bytes on these early failures, eight for IPv4, and thirty for IPv6. The
32-byte input premise supplies all accessed bytes; no invalid-pointer or
missing-memory behavior is tested. Output needs +0..8 on success and +0..4
plus +8..16 on error. The 16-byte output premise includes the inactive bytes
whose preservation is described. These bounds are ordinary
memory premises, not an emulation of target faults.

## Complete static closure and exclusions

`static/authority.json` binds full code bytes, FDE/CIE records, all six named
import relocation/dynamic-symbol/string records, and complete immediate caller
context. GNU and LLVM exports preserve every byte; their 81-row primary
partitions agree exactly with independent Capstone decoding. No masks or LOCK
prefix joins are needed for the primary body. Full-image SHA-256 admission is
distinct from below-admission changed-byte controls.

The sole observed relocated entry slot is `0x5776490`; its call is
`0x4f78970` in the complete `[0x4f78960,0x4f78a2b)` wrapper. That wrapper's
slot `0x5773d08` is called from `0x22c5c3b`, `0x4391062`, `0x47b68fa` in
three complete NodePort contexts. These contexts establish integration edges
only. The wrapper's runtime registration/context helpers and unwind cleanup
are not recovered by this contribution. The selected helper itself has a zR
CIE and no LSDA. No static table/literal or private direct callee participates
in its ordinary body. Dynamic linking and libc remain explicit external edges.

The verifier checks the complete primary and context bytes and unwind records,
actual named dynamic-symbol bindings, unique selected relocations, call-site
encodings and the scoped xref census. Corruption controls below full-image
admission change branch tests, widths, sockaddr offsets, argument constants,
error packing/storage, cleanup and return identity, plus each import's record,
symbol name and unwind/context bindings. They test rejection of altered
evidence, not execution of altered target instructions.

## Scope of this contribution

This is a conditional static relation at ordinary libc import boundaries.
It does not implement or execute a native listener, replay behavioral vectors,
recover the application ABI, or establish compiled-byte equivalence. The
public-source build in `source-build/` is a separate measured candidate. No
component or end-to-end gate follows from these results.
