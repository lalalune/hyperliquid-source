# Node115 length framing and its actual H2 constructor

Target: Linux x86-64 node115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses are linked ELF virtual addresses; ends are exclusive.

This is a decoder value reconstruction and a specific public-dependency
integration boundary. It does not identify a private peer protocol, process
untrusted packets in a running node, or establish current-network compatibility.
No captured instruction, socket, key or chain operation is executed.

## Complete selected bodies

| Role | FDE interval | Bytes |
| --- | --- | ---: |
| Length decoder | `0x5cff0b0..0x5cff5f4` | 1,348 |
| Framed-read builder | `0x16e4bc0..0x16e4d6a` | 426 |
| Actual H2 constructor | `0x1717af0..0x1717c21` | 305 |
| H2 buffered wrapper | `0x16b56f0..0x16b58bd` | 461 |
| Buffer prefix split | `0x161d6b0..0x161d81d` | 365 |
| Shared-buffer promotion | `0x161d5f0..0x161d6ac` | 188 |
| Polling caller A | `0x159a6e0..0x159a9d8` | 760 |
| Polling caller B | `0x1716c60..0x1716f58` | 760 |

The three primary bodies total 2,079 bytes. All eight total 4,613 bytes and
1,067 instructions. Complete bytes, FDE/CIE records, selected actual writers,
RIP references, native GNU/LLVM outputs and LSDA call-site rows are retained.
LSDA action records and personalities remain uninterpreted. Context inclusion
does not recover complete asynchronous polling or ownership semantics.

The decoder is bound by the unique RELATIVE writer at `0x64e0c00`. A full
`.text` E8/E9 and RIP-indirect FF15/FF25 candidate scan, followed by complete
containing-FDE decoding, finds one builder call (`0x1717b5f`) and six decoder
calls (`0x159a73e`, `0x159a764`, `0x159a8ff`, `0x1716cbe`, `0x1716ce4`,
`0x1716e7f`). This is a census of these opcode/slot forms, not complete indirect
reachability. The two polling callers can invoke the decoder before or after
opaque input/EOF/error operations; those operations are not simulated here.

## Admission and memory premises

The native relation assumes valid ordinary mapped, finite, nonwrapping storage;
stable initialized configuration and input bytes; disjoint output/configuration
and buffer metadata; valid native byte-buffer ownership; normal stack/control
state; and normally returning helpers that preserve unrelated live bytes.
Imported memcpy must copy the selected bytes. Allocation, promotion, reference
count guards and reserve must succeed when reached and preserve logical contents.
No aliasing, MMIO, invalid ownership, concurrent payload mutation, panic handling,
resource exhaustion or unwind semantics are included.

The safe Rust crate accepts an immutable byte slice and returns a decision and
consumption count. It neither follows native pointers nor performs the native
allocation/refcount operations. A frame is the original slice interval
`consumed - frame_length .. consumed`. Reservation fields describe the logical
additional capacity demand, not the number of calls or allocated bytes. Inactive
native result bytes, object padding and unrelated registers are not invented.
The raw decoder tests low dword state exactly one; the Rust states admit only
Head and Data(n). Other raw state representations are not a private ABI claim.

## Configuration and constructor

The relevant native fields are: optional skip presence byte `+0`, skip payload
qword `+8`, maximum qword `+0x10`, field width `+0x18`, offset `+0x20`, signed
adjustment `+0x28`, big-endian byte `+0x30`, state low dword `+0x38` and pending
frame length `+0x40`. These are observed raw offsets, not recovered Rust layouts.

The builder's scalar projection at `0x16e4c4a..0x16e4c8d` caps the configured
maximum by the representable unsigned field maximum, adjusted with unsigned
saturation by the signed adjustment. For the exposed API, width is 0..8 and
maximum is any u64; adjustment covers all i64 values including MIN. Width zero
has representable maximum zero; width eight has u64::MAX. The builder can reach
other raw widths, but those are outside this scalar API and later decoding
rejects widths above eight. No global builder validity policy is inferred.

The actual H2 caller initializes a three-byte big-endian field at offset zero,
adjustment +9, explicit skip zero and initial maximum 0x800000 before the builder
call at `0x1717b5f`. The wrapper at `0x16b57c3` copies the whole 0x1d0-byte object
to output without relocating these leading fields and supplies header-list
budget 0x1000000 at `+0x388`. The outer caller then requires its supplied maximum
m to satisfy `0x4000 <= m <= 0xffffff` (`SUB/CMP/JAE` at `0x1717b6f..7c`), writes
m at `+0x10`, and sets the continuation allowance at `+0x390` to
`max(5, q + floor(q/4))`, q=floor(0x1000000/m). Over this admitted interval q is
1..1024, so no division by zero or arithmetic overflow occurs. `h2_limits()`
returns exactly these configuration values and allowance; it does not implement
H2 frame-type, HPACK or CONTINUATION validation.

Actual diagnostic descriptor `0x640ce08` names the vendored
`h2/src/codec/framed_read.rs`; selected Tokio descriptors name an unversioned
vendored `tokio-util/src/codec/length_delimited.rs`. Licensed official source
corroborates the structure, not a unique original crate revision or unmodified
vendor tree.

## Decoder decision order

In Head state, add offset and field width with overflow detection. This is done
before testing buffer availability (`0x5cff17b..181`). Let h be that sum and
k be the explicit skip when present, otherwise h. Required header availability
is max(h,k). If the buffer is shorter, return NeedMore without consuming bytes,
changing state or checking the field width or adjustment.

Once the header is available, width must be at most eight. The copied field is
zero-extended and assembled in the selected byte order; the big-endian branch
uses BSWAP at `0x5cff289`. Width zero reads no bytes and yields zero. The decoded
unsigned number is compared against the maximum before adjustment
(`0x5cff360..364`). Exceeding it reaches the bound invalid-data constructor and
leaves the input/state unchanged.

A nonnegative adjustment is added with carry detection. A negative adjustment
is negated with signed overflow detection before unsigned subtraction
(`0x5cff38a..3d1`). Therefore i64::MIN reaches the negation failure boundary,
even if the decoded value could mathematically accommodate its magnitude.
Other underflow/overflow reaches the separate invalid-input boundary. The
47-byte diagnostic is exactly `provided length would overflow after adjustment`.
These are distinct native boundaries; the analysis Status enum is not an
original error discriminant. Maximum rejection takes priority over either
adjustment failure.

After successful adjustment to n, advance the input by k and reserve logical
additional demand max(n - remaining_length, 0), then set Data(n)
(`0x5cff495..49d`). Header bytes read through a cursor did not themselves consume
input; explicit skip zero retains the entire header. Data state waits if fewer
than n bytes remain. It does not reparse the header or recheck maximum/adjustment.
This is observable when a frame arrives in multiple fragments or configuration
changes between calls.

When at least n bytes remain, the bound split helper is called with n, the state
is reset to Head, and the next header demand is calculated. The returned frame
is the first n remaining bytes, including an empty frame for n=0. Its native
Option niche requires the valid buffer's nonzero pointer; arbitrary malformed
raw pointer zero is excluded. A post-split header-sum overflow occurs after
consumption and state reset, which the value projection preserves as a boundary
result. No later frame is decoded in this single step.

For the actual H2 configuration, only the first three bytes are required to
learn the payload size. The decoder then waits for payload+9 bytes and returns
the complete nine-byte header plus payload because skip is zero. It checks the
payload number against the supplied H2 maximum before adding nine. It does not
require all nine header bytes merely to enter Data state.

## Split and promotion boundaries

The decoder's split slot `0x64e08e8` resolves to `0x161d6b0`. It compares n with
the input length before its copy. Under valid ownership it obtains shared
ownership, snapshots the 32-byte buffer view, advances source pointer by n,
reduces source length/capacity by n, and writes n into the returned length and
capacity fields (`0x161d74b..794`). This proves the prefix/remainder byte relation
under the stated helper and ownership premises; it is not a concurrency proof.

The complete promotion helper `0x161d5f0` retains the logical pointer/length/
capacity fields of the original view and writes the shared-control pointer at
`+0x18`. Its allocations, encoded offset validity and cleanup remain premises.
The split helper's LOCK increment can fail its signed guard; normal-return
qualification excludes that path. Reserve and destructor internals remain
opaque, as do the whole polling callers. Merely returning normally from an
arbitrary substituted helper is insufficient: byte-preservation and view
postconditions are required.

## Qualification scope

28,360 integer/slice expectations were frozen before this new Rust source was
created. They cover all field widths in 0..8, both byte orders, selected full
scalar boundaries, raw width-nine rejection, skip modes, fragmented real H2
headers, empty frames, data-state precedence and arithmetic failure ordering.
The Python oracle uses unbounded arithmetic and byte conversion; Rust uses
checked branch evaluation and byte accumulation. The fixture count is evidence
of tested examples, not a substitute for the domain arguments above.

Rust1.94.1 and1.95.0, opt0 andopt3, match all113,440 observations. Twelve compiled
mutants return normally and produce detected value differences. Input-only
clients never receive expected outputs. Four Rust unit tests additionally check
fragmented header/data flow, maximum-before-adjustment, empty frames and deferred
configuration checks. All executed programs are independently authored Rust,
not captured code or an instruction emulator.

Exact source identity, ABI integration, async reads/EOF behavior, full error
objects, allocator/refcount concurrency, original toolchain, full-node operation
and compiled-target byte equality remain open. No component gate or byte-window
credit is advanced.
