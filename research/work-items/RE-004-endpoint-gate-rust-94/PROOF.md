# Two endpoint gates and the surviving span register

This proof binds node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
ELF VA `[0x3cd2460,0x3cd2490)`. It projects the full numeric RAX/RDX
pair and the ordered ordinary-memory reads. It assigns no string, encoding,
source type or caller-purpose meaning to the registers.

## Static closure

The 48-byte, 20-instruction leaf has one exact FDE. GNU, LLVM and Capstone
independently agree on all instruction boundaries and bytes. All nine
conditional/unconditional branch destinations are instruction starts inside
the leaf; both returns are included. There are no calls or static data
loads. The next FDE begins exactly at the leaf end: there is no padding.
This is the complete caller `[0x3cd2490,0x3cd2d53)`, 2,243 bytes and
521 instructions, containing the only direct E8 candidate at `0x3cd2aa2`.
The caller record is not physically adjacent in the unwind table; the
verifier selects by actual interval, not record order. The complete caller
is decoded to establish that call boundary and target, not to claim its
other behavior. The full RELA scan finds no naming addend and no writes
overlapping either retained code interval. Indirect/computed entry paths
remain unenumerated. Exact FDE/CIE bytes, section mappings, disassembler
exports and 20 downstream corruption controls are retained.

## Full-domain register relation

Let M=2^64 and incoming RDI=a, RSI=b, RDX=p, RCX=n, all unsigned
64-bit values. The first three instructions copy p into RAX and calculate
RDX=(b-a) mod M. No later instruction writes RDX. Thus **every normal
return**, including every rejected gate and an underflowed initial span,
retains this value. The failure block writes EAX=0, zero-extending RAX;
it does not zero the span. A RAX-only or Boolean-return replacement loses
an observable result.

SUB's carry flag determines whether b<a in unsigned arithmetic. If so,
the function returns `(0,(b-a) mod M)` without any byte read. Otherwise:

1. If a>n, reject. If a=n, skip the first byte read. If a<n, read the
   byte at `(p+a) mod M` and reject when its signed value is less than -64.
2. Only after step 1 passes, if b>n, reject. If b=n, skip the second
   byte read. If b<n, read `(p+b) mod M` and reject when its signed
   value is at most -65.
3. Return `((p+a) mod M,(b-a) mod M)`.

Both signed conditions reject precisely unsigned bytes 128 through 191.
For byte x, `x & 0xc0 == 0x80` is equivalent to membership in that
interval. The Rust mask therefore implements both target comparisons
without relying on host signed-overflow behavior. Values 0x7f and 0xff
both pass. This is a boundary-byte predicate, not an encoding validator.

The new code calculates the wrapped span once, uses the two ordered
unsigned checks, applies the byte predicate only at the selected stages,
then returns the wrapped base addition. Its early returns share the
unchanged span. These statements cover every path; there is no loop,
helper or dependency on incoming flags/SIMD state. `a=b=n` skips both
reads, even for an empty image or an arbitrary base. A passing addition
can wrap to zero. Consequently a zero RAX is not assigned an Option-like
failure meaning by the API.

## Memory admission and short circuits

The readonly image at numeric base B represents byte address B+j for
every slice index j. Its last byte must fit a u64 address; a final byte
at M-1 is allowed. An empty image has no address-range requirement. An
invalid overall image yields the new `ImageRange` error before evaluation.

Each reached byte address is first reduced modulo M, then checked for
membership in the nonwrapping image. `checked_sub`, fallible usize
conversion and slice `get` establish that membership without a guessed
relationship between the limit n and the image length. A base or index
need not itself be in the image. Repeated endpoints and arbitrary aliases
are admitted because memory is readonly and stable.

Missing reached bytes give `Start` or `End`. These are new safe API
refusals, not original fault observations. Their ordering matters: with
`a=0,b=2,n=1` an unavailable start byte produces `Start` even though the
later end bound rejects. A start byte of 0x80 instead returns normally
with `(0,2)` and never reaches the end check. Globally testing both limits
first would change the new admission policy; the compiled `end_precheck`
control distinguishes this using 666 refusals, and is not presented as
666 changed original normal returns.

Correspondence requires actual reached target byte accesses to be readable
ordinary stable memory, with valid instruction/control storage. Abstract
high or wrapped address fixtures do not assert that every such address
can be mapped on Linux/x86-64. Unmapped target faults, instruction/control
aliases, MMIO, concurrency, timing, flags and other registers are outside
the projection. There are no writes. This is a safe value API, not a
System V ABI replacement or recovered original source signature.

## Independent expectations and qualification

Before the Rust directory existed, `oracle.py` froze inputs, expectations
and its own hash. It classifies bytes with Python unbounded signed values
and evaluates ordered read obligations against an immutable image; the
Rust uses a bit mask, separate branches and checked slice access. No target
execution, instruction emulator, copied reference implementation or Rust
output feeds the expectations.

The fixed 77,935 rows include every one of 65,536 endpoint-byte pairs,
768 same-index/skipped-endpoint cases, unsigned high-bit boundaries,
span underflow, numeric address and return wrap, exact final-byte access,
invalid whole images and both missing-byte stages. There are 73,859
normal-return records, 2,051 ImageRange, 1,827 Start and 198 End refusals.
This corpus exercises boundary witnesses; the path proof above supplies
the all-input argument under the explicit domain.

Two builds each at opt0 and opt3 match every output byte (311,740
observations), with identical repeated library/client/output hashes at
each optimization. Three unit tests per profile, malformed driver input,
and changed-row/missing-byte comparator controls pass. All 16 compiled
mutants differ: retaining no span changes 72,514 normal-return records;
using unsigned byte ordering changes 33,008 normal-return records and
132 refusal records. Results distinguish admitted records from new
refusals for every mutant. Exact commands, compiler/linker/source hashes,
first witnesses and all 138 raw command streams are archived losslessly.

The native host is aarch64 macOS using actual rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`. These runs execute only the
newly authored Rust client. They do not establish target compiled-byte
identity, original ABI compatibility, whole-node equivalence or a
completed foundation gate.
