# RE-014 / foundation: three node115 wrapper bucket-state routes

Target node115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105896032bytes; base8fd8db680ec4bfef40996e5616bce3d5156d0b86. One bounded
family: which raw byte route reaches a direct callee, and what unsigned bucket
word/activity observation is produced in the other selected phase? These are
partial native-state projections, not recovered whole ensure-orders methods.
All92full-component gates remain false; no machine-byte identity credit.

## Original bytes, phases and unknowns

Three actual FDE-described owners, each630bytes/163instructions,1890bytes total:
`0x2d1d600..0x2d1d876`, `0x5185200..0x5185476`, `0x5185480..0x51856f6`.
Full original exports, hashes, actual FDE/CIE and file offsets are retained.
The label `hyperliquidity_ensure_orders` is byte-bound at each native RIP LEA
with a28-byte descriptor length. This is a use-context label, not proof of
source function/type ownership. All helper addresses are identities only;
source module ownership and complete caller/operation closure remain unknown.

For each start A, the selected byte test at A+0xdb uses supplied BPL. Nonzero
reaches A+0xe0 before argument setup/call at A+0xec; its tail jumps to A+0x211,
skipping the local path. **DirectHandoff is before that callee**, not a completed
return or a claim that the callee preserves state. Incoming R8D is copied into
EBP at entry, but preceding helper effects are not reconstructed: the compared
byte is an explicit post-helper boundary input.

Zero byte reaches A+0xf6. A preceding scalar/calendar-like conversion is not
modeled. The static audit separately checks that this local segment has no
calls or memory writes, does not change R12 and has internal branch targets;
its conversion semantics, valid date fields and output reachability remain
unclosed. The next explicit boundary A+0x198 supplies the raw RCX word and a
field snapshot, not a substituted conversion/helper call.

TEST/CMOVG clamps the signed raw word to positive-or-zero. Divisor is the actual
u64 read at R12+0x20. The native OR/SHR dispatch selects DIV32 when combined high
bits are clear, DIV64 otherwise. Previous word at R12+0x28 is loaded after the
divide. Only unsigned quotient>previous stores the quotient there. The same
unsigned predicate becomes the byte at RSP+0x50, even after label-pointer and
length stores; those MOV/LEA instructions preserve the comparison flags.
Local context/raw-double stores and the subsequent labelled continuation
remain outside the Rust result. The flag is not claimed to govern operation
execution, logging, timing, cadence or any economic policy.

Zero divisor: the actual decoded DIV operand is examined at its actual native
instruction boundary; the interpreter stops **before** the fault. Z is an own
boundary classification, not an original recoverable error, trap semantics or
function return. A displacement corruption that loads the previous field as
divisor changes Z to a successful numeric route, proving the boundary check
uses decoded operands rather than the supplied divisor parameter.

## Frozen expectations and owned Rust

Native freeze4897719e precedes the new115 Rust component. The policy was already
explored in Python; no claim of blind recovery. No unlicensed inferred source
was copied, no historical Rust transferred and no machine bytes transplanted.
The one-time producer refuses an existing component even under Python-O;
original captures are hash-checked before/after private COW corruption tests.

8952physical rows = (2786local-route logical inputs +198direct-route logical
inputs) times3owners. The full native stream retains division-width metadata.
Rust comparison explicitly excludes that field: D is direct-callee boundary,
Z is pre-DIV0 boundary, T carries quotient/post-field/active byte. Hashes for
both full and semantic streams are frozen. Expected values come from actual
parsed target instructions; the separately linked client reads inputs only.
27smoke rows were selected from that already-frozen corpus before Rust.

Eighteen actual private instruction corruptions change native observations:
15change the Rust semantic projection,3change native division-width metadata
only. Five actually compiled Rust mutants produce297/549/2085/1134/1092mismatches
and each fails the same frozen smoke. Original opt0/opt3 match all8952rows;
own opt3 rlib repeat is identical. Research rustc1.94.1(e408947bfd),LLVM21.1.8,
aarch64-apple-darwin,edition2021,no dependencies or invented Cargo graph.
Freeze passed15.972wall seconds; native regeneration/build/clients/controls
passed93.119s, serial10%active-duty control; process priority unavailable.

Rust uses an own Route and ordinary `&mut u64`. It reports D/Z before opaque
handoff/trap; it updates the ordinary previous word for T and returns bucket /
activity. The zero-divisor check is reordered before clamp in the safe API;
only the boundary classification is compared, with register/flag state,
original object ABI, compiler write trace, aliasing and concurrency excluded.
No complete native call, original Result enum or thread-safety claim.

```sh
python3 research/work-items/RE-014-liquidity-bucket-115/build.py --rustc <rustc1.94.1> --output work/liquidity-bucket-new
python3 research/work-items/RE-014-liquidity-bucket-115/audit.py --objdump <GNU-objdump>
python3 -m unittest discover -s tests -p test_node115_liquidity_bucket.py -v
make doctor verify catalogue-check
make reproduce
```

Actual scoped outcomes are recorded in validation.txt. Earlier same-base full
make test reached1800s at file10/77; first9completed. The full suite remains
incomplete, never a PASS; hosted CI is unobserved. No captured process, network,
chain, signing or wallet effects. This is a bounded reverse-engineering result,
not a production bug claim or full-component gate. Next: close the preceding
conversion and labelled continuation before composing whole wrapper behavior.
