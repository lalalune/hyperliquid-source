# COMISD normal-return domain and full AL-only result

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete FDE is `[0x5028a40,0x5028a5b)`, 27 bytes/six instructions.
The predecessor bound its low-byte comparison and warned about upper RAX;
this implementation adds the complete numeric RAX, safe image admission
and explicit comparison-exception domain without executing floating-point
instructions or emulating captured code.

## Exact memory and register relation

Let O be original RSI and M=2^64. The first load reads a little-endian
u64 pointer P from address `(O+0xf38) mod M`. MOVSD then reads eight bytes
at P into the low XMM0 lane. It does not alter RAX, which still contains
all bits of P. The comparison reads the bound eight-byte constant at
linked `0x20a730`: `000000000000f03f`, binary64 positive 1.0 exactly.
This literal is in read-only `.rodata`, has no overlapping relocation and
is assumed unchanged and readable in the original module.

The actual opcode is `66 0f 2f`, **COMISD**, not `66 0f 2e` UCOMISD.
For a normally completing comparison, unordered/less/equal/greater give
CF respectively 1/1/0/0. Unordered also has ZF=PF=1; equality has ZF=1
and CF=PF=0. SETAE depends only on CF=0. It writes AL, not EAX or RAX.
Thus, with gate g=1 exactly for ordered payload >=1.0,

`RAX = (P & 0xffffffffffffff00) | g`.

The upper 56 pointer bits survive on both true and false comparisons;
there is no full-width boolean return. No data is written. Other registers,
XMM0, flags, MXCSR status updates, return-stack effects and ABI are outside
this value projection. Incoming RAX is irrelevant because the pointer
load replaces all of it.

Intel's primary [volume 2A, COMISD, pages 3-186–3-187](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf)
specifies the encoding, ordered/unordered flags and exceptions: COMISD
signals invalid operation for either quiet or signaling NaN; UCOMISD's
NaN rule differs. An unmasked SIMD exception prevents the usual EFLAGS
update. Invalid and denormal operand are the listed SIMD exceptions.

## Complete binary64 partition

Write the raw payload as sign S, exponent E (11 bits) and fraction F
(52 bits). The categories are exhaustive:

- E=2047,F!=0 is NaN, of either sign and either quiet/signaling class.
- E=2047,F=0 is signed infinity.
- E=0,F!=0 is a signed subnormal/denormal.
- E=0,F=0 is signed zero.
- Remaining inputs are signed finite normal numbers.

Let magnitude be the raw bits with the sign bit removed. The source's
`magnitude > 0x7ff0000000000000` detects exactly all NaNs. Its nonzero
magnitude below `0x0010000000000000` detects exactly all subnormals,
excluding both zeros. Neither test conflates infinity and NaN.

For finite positive normals, the exact value is
`(2^52+F) * 2^(E-1023-52)`. If E>=1023 it is at least one; if E<1023 it
is strictly less than one even when F is maximal. Positive infinity also
qualifies. Negative values, either zero, every subnormal and masked NaNs
do not qualify. Consequently g=1 exactly when the **unsigned raw bits**
lie in the closed interval
`[0x3ff0000000000000,0x7ff0000000000000]`.
The interval includes 1.0 and positive infinity, excludes every NaN and
all negative encodings, and correctly handles adjacent representable values.
This is an integer bit relation, not a host floating-point comparison.

## Comparison modes and normal completion

`CompareMode` supplies only the three original control settings that can
matter: invalid-operation mask IM, denormal-operand mask DM, and DAZ.
They describe original execution and never change the host environment.
They are booleans, not a complete/raw MXCSR value. Driver bits0/1/2 merely
encode these three booleans; actual MXCSR uses IM bit7, DM bit8, DAZ bit6.

The complete comparison-domain rule for the fixed normal second operand is:

- Any NaN requires IM=1 for ordinary completion through SETAE/RET.
- A subnormal with DAZ=0 requires DM=1.
- DAZ=1 permits the subnormal comparison independently of DM.
- All other payloads require neither of these exception masks.

The two exceptional operand categories are disjoint. `InvalidOperationUnmasked`
and `DenormalOperandUnmasked` are new safe refusals of that ordinary domain,
not claimed original return values or implementations of a signal handler.
An external handler could alter state or resume execution; that behavior
is excluded rather than treated as an unconditional process non-return.

Intel's [volume 1, sections 10.2.3.1, 10.2.3.4 and 11.5.2.2](https://cdrdv2-public.intel.com/671436/253665-sdm-vol-1.pdf)
defines these masks and DAZ. DAZ replaces subnormal operands with signed
zero and suppresses the denormal-operand exception even when DM is clear.
FTZ does not govern denormal-input exceptions. Here both the original
subnormal and its DAZ zero are below positive 1.0, so DAZ changes admission
but never g. There is no rounded floating result; rounding control and
FTZ do not change this comparison's returned gate. Status/sticky flags
and arbitrary surrounding floating-point behavior are not projected.

## Numeric memory image, aliasing and refusal order

`compare(image, image_base, object, mode)` accepts a stable byte image of
numeric addresses `[image_base,image_base+len)`. Its exclusive endpoint may
equal M but cannot exceed it; the u128 check cannot overflow on any Rust
host. Object is the original O, not an offset or a Rust pointer.
The field address explicitly wraps modulo64. Checked subtraction from
image_base, checked usize conversion, checked addition of eight and `get`
require each complete qword to fit the nonwrapping image. No unchecked
indexing or pointer conversion is used.

Admission proceeds exactly in the relevant read order: image description,
field qword, payload qword, comparison domain. Missing field/payload bytes
return `PointerField`/`Payload` before inspecting floating classes or mode.
There is no null-pointer special case: numeric zero can be present in an
image, while original validity remains a separate normal-return premise.
Only the actual field and payload spans are required; the rest of a guessed
object layout is never demanded. The threshold literal is statically bound,
not another optional image span.

The two data reads may overlap partially or completely. Neither changes
memory, so using the same final immutable bytes preserves every overlap.
The oracle's alias cases construct one final image before evaluating it;
they do not assume requested payload bits survived pointer-field overlap.
The library has no writes on success or refusal. Every safe input has a
finite deterministic result, with no allocation, unsafe code, floating
operation, exception-handler action or overflow panic.

For original correspondence, the supplied bytes must equal the actual
ordered field/payload observations, the bound constant must remain 1.0,
all three original reads must complete normally, the stated controls must
be supported/enabled, and ordinary instruction/return control must hold.
Faults, invalid/noncanonical machine mappings, MMIO, concurrent mutation,
runtime-patched constants, CET/ABI details and handler effects are excluded.
Synthetic numeric addresses can test wrapping without asserting that a real
process maps them. The source returns numeric RAX only, never dereferencing
its modified low-byte address.

## Static closure and independent qualification

The static verifier binds all 27 bytes, full FDE/CIE, preceding/following
FDEs and separate padding; GNU, LLVM and Capstone agree on all six boundaries.
It verifies the actual COMISD RIP displacement to the full constant and
its section/PT_LOAD mapping. The single entry naming slot `0x5759108`
has a raw-zero qword and one exact symbol-zero RELATIVE record. Every
80,300-record RELA scan checks its unique complete writer and rejects
any partial relocation over the constant or code/padding. Full `.text`
E8/E9 scans find no direct candidates; indirect reachability/provenance is
not reconstructed. There are no helper calls or unresolved import semantics.

Before Rust existed, static evidence, the independent oracle and all
inputs/outputs were hash-frozen. The oracle reads a numeric-address map,
forms an exact integer significand/exponent value and compares that rational
value with one. Its byte-bucket reconstruction uses division/multiplication
by256. The source instead uses a raw u64 interval and bit masking. Neither
side calls the other or runs captured instructions. The new native client
reads only image/metadata/mode inputs and returns tagged full-RAX values.

Coverage includes all 2,048 exponents, both signs, three fraction endpoints,
additional quiet/signaling NaN and subnormal patterns under all eight modes,
every pointer low byte, high addresses, exact range ends and overlapping
reads. Compiled controls attack COMISD-vs-UCOMISD invalid behavior, DAZ and
mask admission, threshold edges, pointer upper bits, byte order and memory
ranges. Finite experiments qualify this proof and implementation, not every
possible memory image, original compilation or whole-node behavior.
