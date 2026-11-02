# Two signed affine table paths: complete normal-return value proof

Target node94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The exact FDE is `[0x5560660,0x55606a8)`: 72 bytes, 21 instructions,
including the five-byte NOP at `0x556068b`. Eight following `int3` bytes
are padding, not part of this function. `static.json` binds every byte,
the FDE/CIE, next FDE, both complete independent disassemblies and Capstone
boundaries. No captured instructions were executed or emulated.

## Register widths and exhaustive path partition

Let the raw input registers RDI, RSI, RDX be `first`, `mode`, `row` in
`0..2^64-1`. Define `x = first mod 2^32`, `m = mode mod 2^32`, and
`y = signed32(row mod 2^32)`. Let `M = 2^64` and load bias `L` be the
actual offset from linked virtual addresses, interpreted modulo M.

`lea -3(%rdi),%eax` writes the low32 result and zeroes RAX's upper half.
Consequently `g = (x-3) mod 2^32`. The unsigned `ja` after `cmp $2,%eax`
takes the first path exactly when g > 2. For every u32 x, g <= 2 is
**equivalent to x belonging to {3,4,5}**: the only residues of x satisfying
x-3 in {0,1,2} are precisely those three values. Neither x=0..2 nor the
high-bit half of the u32 domain passes this gate.

Only when g <= 2 is `cmp $1,%esi` tested. The second path is taken exactly
when m=1. All other inputs take the first path. Upper32 bits of all three
input registers have no effect: the gates use EAX/ESI, and each index
operand is explicitly sign-extended from EDI/EDX. The implementation uses
the same low32 extraction, wrapped subtraction and unsigned gate.

## Complete effective-address arithmetic

On the first path, `movslq %edx,%rdx` and `movslq %edi,%rdi` yield y and
`signed32(x)`. Two 64-bit LEAs compute `5*y`, then `signed32(x)+10*y`.
The RIP-relative LEA at `0x556067f` fixes linked base A=`0x576d9e0`.
The qword load has scale eight. Thus the selected address is

`a = (L + A + 8*signed32(x) + 80*y) mod M`.

On the second path `movslq %edx,%rdx` yields y. `cltq` sign-extends EAX,
which still contains g: the comparisons and branches did not change it.
Here g is proven in 0..2, so this extension is just g. LEA and ADD compute
`3*y+g`; the RIP-relative LEA at `0x556069c` fixes B=`0x576db20`.
The selected address is

`a = (L + B + 24*y + 8*g) mod M`.

There is no final low32 truncation of either index. First-path index lies
in `[-11*2^31, 11*(2^31-1)]`; second-path index lies in
`[-3*2^31, 3*(2^31-1)+2]`. All intermediate index arithmetic fits signed
64 bits, including multiplication by eight (absolute value < 2^38).
The Rust staged i64 wrapping operations therefore equal these exact
signed expressions. Casting a negative index to u64 and multiplying by
eight computes the same residue modulo M as x86 addressing. Addition of
load bias and linked base, or addition of the signed byte displacement,
can wrap; all corresponding Rust operations explicitly wrap. No debug or
optimized signed-overflow behavior is relied upon.

Each path performs one `mov (...),%rax`, then `ret`. On a normal return,
**all 64 bits of RAX** equal the selected little-endian qword. The loaded
word is not interpreted as a pointer, truncated, dereferenced or called.
The function writes no data memory and invokes no helper. Only this full
RAX value is projected; flags and the other caller-clobbered registers are
not outputs of the new API.

## Runtime image and safe admission

`lookup(image, image_base, load_bias, first, mode, row)` is a safe Rust
value API, not an original ABI export. The slice describes stable ordinary
bytes at numeric addresses `[image_base, image_base+image.len())`. Its
exclusive endpoint may equal M, but may not exceed M. This is checked in
u128 before any read. Empty images, including one based at `u64::MAX`,
are permitted image descriptions and cannot contain a qword.

After computing a, checked unsigned subtraction establishes a >= base;
checked usize conversion and checked addition of eight establish a host
slice offset and extent. `get(offset..end)` succeeds exactly when every
byte a through a+7 lies in the described nonwrapping image. The bytes-to-
array conversion cannot fail: its preceding range has exactly eight
bytes. Neither pointer arithmetic nor unsafe Rust is used. The library
has no allocation or dependency and no arbitrary index or table-count
limit. On 32-bit hosts a Rust slice itself is bounded by usize; the checked
conversion refuses unrepresentable offsets rather than truncating them.
Native qualification here is only on the recorded 64-bit Apple host.

A failed image description returns `ImageRange`; a missing selected qword
returns `SelectedWord`. These are new safe refusals, not translations of
original faults. There is no precheck of the unselected table, base qword,
or any logical table extent. The function does not mutate the image on
success or refusal. An unaligned qword is allowed if all eight bytes are
present, matching an ordinary successful x86 qword load.

For original correspondence, the supplied bytes must equal the selected
runtime memory bytes, load_bias must equal the actual module bias, and
that original read must normally complete. This premise excludes invalid
or noncanonical machine addresses, inaccessible pages, memory-mapped
side effects, concurrent mutation and faults. The numeric slice API can
also describe artificial addresses not mapped on real hardware; those
are useful mathematical test inputs and do not assert original normal
returns at those addresses. Return-stack/control behavior and instruction
fetch are outside the value projection. There is no timing, atomicity,
original compilation, source-type or binary-identity claim.

## Data and caller closure

Both linked bases are resolved from actual RIP displacements, with their
`.data.rel.ro` section and containing PT_LOAD bound in `static.json`.
They are 320 bytes apart; this distance is **not a table length**.
The first eight file bytes at each base are zero, with exactly one
`R_X86_64_RELATIVE` record each. Their addends are `0x5585670` and
`0x55af100`, respectively. After ordinary relocation these two sample
qwords contain `(L+addend) mod M`, not zero. Frozen cases include these
numeric relocated samples at several biases.

Those two qwords are context samples only. Negative or large signed
indices may address other storage. No finite logical table extent or
constant table contents are invented: the image parameter supplies the
actual bytes at whichever address the complete formula selects. The
API does not treat unrelated file bytes as a fully reconstructed runtime
image. The two sample loaded values are not followed into code.

The full 80,300 RELA records are scanned: no record relocates the leaf,
its following padding or retained caller, and none names the leaf entry.
The only raw E8 candidate targeting the entry is `0x55c8554`; it is a
confirmed instruction in the fully retained caller FDE
`[0x55c84f0,0x55c8bc3)`, 1,747 bytes and 460 instructions. No E9 candidate
targets the entry. GNU, LLVM and Capstone agree on the complete caller
instruction boundaries. Caller identity, arguments on every dynamic path
and its wider behavior are unclaimed. The encoding scan is not a complete
indirect-reference census. No external helper/import contract is needed.

## Independent validation and its limit

Before any Rust source existed, `oracle.py`, `static.json`, all inputs,
all expected outputs and their hashes were frozen. The oracle uses
literal membership in {3,4,5}, Python signed decoding, one unbounded
affine byte-address formula and an immutable numeric byte-address map.
It does not reproduce the Rust wrapped-gate and staged checked-slice
implementation, invoke it, or run a captured instruction simulator.

The finite corpus samples both branches, their dense overlapping address
ranges, all 64 one-bit register positions, u32 signed endpoints, ignored
upper halves, exact span ends, unaligned reads, load-bias wrapping and
refusal paths. Every admitted expectation includes an actual eight-byte
read with nonuniform contents. Exact eight-byte data and refusal tags are
compared without masks. Native compiled controls perturb gate widths,
signedness, coefficients, linked bases, scales, wrapping, read endianness,
returned width and admission. Address errors spanning many gigabytes can
produce safe-refusal differences in the compact images; they are reported
separately from cases where both implementations return different values.
No enormous physical table or arbitrary runtime cap is introduced.

The proof covers the full specified value domain. The corpus and actual
native controls test that the new implementation and qualification path
realize that proof; they are neither exhaustive testing of all registers
nor differential execution of node94.
