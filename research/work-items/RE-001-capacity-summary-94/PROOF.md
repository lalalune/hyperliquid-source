# Static argument: record selection, scaled arguments and worker cleanup

The authority is the two complete node94 FDEs and data bindings in
`records.json`, authenticated against the full target SHA-256. This proof uses
ordinary x86-64 calling-convention assumptions, a readable stable array of N
112-byte records with nonwrapping `112*N` and address arithmetic, successful
allocations, and normally returning helpers. A valid formatter result has
capacity C in 0..2^63-1 and valid pointer/length ownership fields. These are
explicit preconditions, not recovered contracts of the omitted helpers.

## Input relation and stable maximum

The selector receives its output pointer in RDI and object pointer in RSI.
At `0x13cc10e` it reads N from object+0x190. N=0 branches directly to the
empty-result path. Otherwise it retains the output pointer, reads the array
base from object+0x188, and computes `112*N` at `0x13cc12a`. RBP begins at zero
and advances by 112 at `0x13cc153`; the equality test at `0x13cc15d` terminates
at the computed byte extent. No bounds check or overflow refusal is inferred
for malformed pointers, counts or objects.

For each record at base+RBP:

- `0x13cc166` loads unsigned A from +0x58 into R15.
- `0x13cc16b` loads unsigned B from +0x60 into RAX.
- `CMP RAX,R15; JBE` at `0x13cc170..0x13cc175` admits B<=A.
- B>A takes the invalid-record route. It tests the DWORD at `0x577ab98` and,
  if nonzero, requests the existing Once boundary. On normal return it restores
  the loop extent, base, current result length, saved maximum and validity flag.
  It neither replaces the summary nor admits that record.

The current maximum is carried in R14, with R13B as a separate valid flag.
`CMP R15,R14; SETBE CL; TEST R13B,CL` at `0x13cc190..0x13cc19d` keeps the
previous result iff a valid record already exists and A<=the saved maximum.
Before the first admitted record, R14 need not be initialized: R13B=0 makes
this keep predicate false regardless of the comparison. An admitted record
sets BL=1; the next loop step transfers it to R13D.

Induction on processed records gives: whenever the valid flag is set, the
saved raw maximum is the largest admitted A so far and the retained formatted
record belongs to its **first occurrence**. A strict increase replaces it;
an equal or lower A does not. Invalid records preserve the invariant. Each
strict increase triggers another format request, so a monotonically increasing
sequence can format N times, not just once after a complete maximum scan.
The relation is about raw unsigned values, before the following clamp.

## Clamp, difference and argument order

At `0x13cc19d..0x13cc1b8`, L=`0x7fffffffffffffff` and the unsigned CMOVs set
`a=min(A,L)` in RCX and `b=min(B,L)` in RAX. The independent clamps matter:
this is **not** a clamp of the raw difference. Since admitted records have
B<=A and min is monotone, `0<=a-b<=L`.

The instructions at `0x13cc1b8..0x13cc1d5` form d=a-b. They include the
usual signed division bias `(2^30-1)` and choose the unbiased d when d is
nonnegative, then arithmetic-shift by 30. For the admitted domain the negative
arm is unreachable: the first result is exactly floor((a-b)/2^30). RCX is
logically shifted at `0x13cc1da`, giving floor(a/2^30) as the second result.
No floating point, rounding to nearest, or subtraction of separately rounded
quantities occurs.

| Boundary | First numeric argument | Second numeric argument |
| --- | ---: | ---: |
| A=0, B=0 | 0 | 0 |
| A=2^30, B=1 | 0 | 1 |
| A=L, B=0 | 8,589,934,591 | 8,589,934,591 |
| A=2^64-1, B=L | 0 | 8,589,934,591 |
| A=2^64-1, B=2^64-1 | 0 | 8,589,934,591 |

For example totals L, L+1 and 2^64-1 all have the same clamped total but
remain strictly ordered for selection. A later larger raw total therefore
replaces the earlier result even if a formatter could render the same text.

At `0x13cc1de..0x13cc208`, the first argument descriptor points to the scaled
difference at stack+0x58. The second points to the scaled total at stack+8.
Both callback words come from `0x576e9d0 -> 0x1570740`. The format request at
`0x13cc219` passes output stack+0x60, program `0x1e938e`, and these ordered
descriptors to `0x576e040 -> 0x1344760`.

The program's five retained bytes are `c0 01 2f c0 00`. Under the already
published format interpretation (#633/#1330), they request one argument,
ASCII slash, another argument and termination. That interpretation and the
general renderer are prior work, not a new recovery here. This packet proves
the actual argument values, order, callback binding and program address.
The integer callback and complete rendering/allocation/error contracts remain
external; no execution of a rendered string is claimed. The 2^30 divisor is
observed; calling the upstream fields bytes or a particular kind of capacity
requires the builder's field provenance, which remains open.

`arithmetic.py` checks 45 admitted boundary pairs, 11 signed-division boundary
values, 4,100 release-capacity values and the option-store union described
below. It uses ordinary mathematical integers. It is not an instruction
interpreter, original selector execution or evidence of runtime equivalence.

## Retained result, replacement and empty output

R12 initially holds `0x8000000000000000`, denoting no retained formatting
result in this local control flow. The format request writes a new three-word
record at stack+0x60/+0x68/+0x70. Before installing it, the selector computes
`(2*old_capacity) mod 2^64` at `0x13cc21f` and skips the release call when that
word is zero. Exactly two u64 capacities satisfy this predicate: zero and the
initial sentinel. For ordinary nonempty capacities 1..L it calls
`0x576e010 -> 0x54c8cb0` with the old pointer, capacity and zero flag.

At `0x13cc246..0x13cc25a`, the new capacity, pointer and length are loaded into
R12, stack+0x10 and R8. On the final retained-result path, `0x13cc2ed..0x13cc2f8`
writes them to output+0/+8/+16 and returns the output pointer in RAX. Thus
ownership of the normally retained helper result is projected, not a borrow
of record bytes. Exact allocator and Rust String/Vec types are not recovered.

If no format result was installed, `0x13cc2be` detects the sentinel. The
empty-input and all-invalid paths also request the shared Once boundary when
the observed state DWORD is nonzero, then produce **(0,1,0)**. Even an empty
input is therefore not an unconditional side-effect-free return. If the helper
were to violate the valid result-domain precondition and itself return the
reserved sentinel, the simple “admitted record implies retained-result path”
conclusion would not follow; this proof does not invent that helper behavior.

The landing-shaped code `0x13cc34d..0x13cc375` guards release of the retained
old result with the same doubling predicate and calls `_Unwind_Resume@plt`.
The entire range is exported, but LSDA call-site/type/action tables are not
decoded. No exception-complete or arbitrary-unwind ownership claim is made.

## Worker construction, ordering and disposal

The fixed worker's first two data stores (`0x1400ea2`, `0x1400ea7`) write
`0x0101010101010101` at stack+0x15 and stack+0x10. Their union initializes
exactly thirteen bytes, offsets 0x10..0x1c inclusive, all to one. This says
nothing about any fourteenth byte or the source-level meaning of each option.

The normal request order is:

1. `0x1400eb9`: call `0x576ef60 -> 0x4f3a270` with an output object at
   stack+0x28 and the thirteen-byte option span at stack+0x10.
2. `0x1400ec7`: call the selected selector through `0x576e9c8`, reading the
   built object and writing its result to stack+0x10.
3. Test the existing first Once state at `0x577ab98`; if nonzero, request
   `0x4ee3b20` at `0x1400f44` with cell `0x577ab80`, flag 1, callback table
   `0x5669f68` and Location `0x5669f50`.
4. Load the second object through `0x576eb70 -> 0x577a898`; test its DWORD
   +0x268. If nonzero, request the same Once helper at `0x1400f77` with that
   state, flag 1, callback table `0x5668d18` and Location `0x5668cd8`.
5. At `0x1400ee8`, read the summary's capacity. If nonzero, call the shared
   release helper at `0x1400ef9` with its pointer, capacity and zero flag.
6. Call external object destructor `0x1407040` at `0x1400f04`, then return.

Both callback-table headers are `(0,8,8)` and their four callable entries are
bound by RELATIVE relocations in `records.json`. Both Locations point to the
same 76-byte `std/src/sync/once.rs` path and encode 219:20. This binds the
caller-supplied data. It does not newly reconstruct Once, either initializer,
or their synchronization, panic and allocation contracts. The first shared
build-mode machinery is already documented by #667/#694.

The worker's normal local path never sends the selected buffer to a publisher,
logger or writer after the selector returns. It releases it before dropping
the built object. This is a **local disposal observation**, not a whole-program
absence of telemetry or side effects: the builder, formatting, initialization
and destructor helpers may have effects. The pointer, lifetime and system
identity of their fields still require closure.

Two retained exceptional entries differ: `0x1400f82` checks/releases the
summary then drops the object; `0x1400f9e` begins at object cleanup. Both
continue to `_Unwind_Resume@plt`; a further retained call at `0x1400fb3`
reaches the cleanup-failure boundary. Their exact LSDA selection is open.

## Incoming context and scope

The qualified census finds the selector call at `0x1400ec7` and worker call
at `0x1451abd`. Each is an instruction start in its completely decoded owning
FDE. The only RELATIVE pointers to these two entries are `0x576e9c8` and
`0x576ef58` respectively. This is the stated E8/FF15/FF25 plus RELATIVE census,
not a claim about every register-indirect caller or runtime reachability.

#1678 already recovers the calling thread callback and explicitly leaves
`0x1400e90` unresolved; those prior bytes are not included in this denominator.
#233 exports the external object destructor as caller context while recovering
its 168-byte-element drop callee; neither body is newly claimed here. General
formatters, Once, the external builder and all deeper helpers remain outside
the two selected FDEs. No component gate or reconstructed first-party byte
count changes, and no captured code or public node traffic was run.
