# Complete wrapper and fixed-seed helper relation

This proof binds node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
wrapper `[0x538c820,0x538c859)` and helper `[0x5422e70,0x5422ef5)`.
It concerns ordinary immutable memory and mathematical return values, not
original ABI, faults, flags, scratch registers or complete caller behavior.

## Domain and closure

The input slice represents the descriptor's pointer and unsigned 64-bit length.
Its bytes are readable ordinary memory with no concurrent or MMIO effects.
Require `input_base + input_length + 4 <= u64::MAX`, as an integer inequality.
This deliberately sufficient premise covers both the end pointer and the
one-word lookahead pointer formed by the helper, including empty input. Merely
having a nonwrapping readable input span is insufficient: the last loop compare
forms an address beyond its final word. Wrapped pointer comparisons are outside
this projection. The slice API accepts all valid slice lengths; the fixtures'
256-byte maximum is a harness limit, not a function cap.

The descriptor, divisor word and selected table byte are readable, with
nonwrapping effective addresses and unchanged code/control state. Read-only
input, descriptor, divisor and table aliases are allowed: no data store occurs
in either function. Supplying slices and a u16 divisor represents the values
of these loads, not their original pointer validity. The only helper called by
the wrapper is the fully retained 133-byte helper, and the helper has no calls.
The complete caller supplies seed-independent descriptor values and observes
AL, but whether its runtime inputs satisfy this domain remains unproved.

For successful wrapper correspondence require divisor `d != 0` and the
selected byte to be within the table slice. The Rust `ZeroDivisor` and
`TableBounds` variants are new policy for inputs outside that successful
correspondence domain. The native zero divisor produces #DE; Rust does not
imitate that fault. A missing table byte would require a memory access in the
native body. No fault order, partial fault effect or native return is invented.

## Hash recurrence

Let `M = 0xc6a4a793`, `n` be the input length, `q = floor(n/4)` and
`r = n mod 4`. Arithmetic marked mod is in the ring Z/(2^32). The initial
value is `h0 = ((n * M) mod 2^32) XOR 397`: the IMUL uses ESI and the wrapper
loads EDX with 0x18d. Taking `n as u32` before wrapping multiplication agrees
for every admitted n, including lengths larger than 2^32.

For each complete little-endian word `wj = sum(input[4j+k]*256^k, k=0..3)`,
set `pj = ((hj + wj) * M) mod 2^32` and
`h(j+1) = pj XOR floor(pj / 2^16)`. The helper's EAX add, ECX multiply,
logical SHR and XOR produce exactly this recurrence. All upper 32 bits of RAX
are cleared by the EAX writes. The safe implementation uses `chunks_exact(4)`
and performs this recurrence without overflow traps.

Under the lookahead premise, R8 is `base+n` and R9 is `base+4`. The initial
unsigned comparison enters the loop iff n>=4. At iteration j, RDX addresses
the end of word j and the memory operand at RDX-4 is exactly that word. RDX
then advances by four; comparison with the end pointer admits exactly q
iterations. For n>=4, `((n-4) & ~3) + (base+4) = base+4q`; for n<4, RDI
remains base. The residual pointer difference is therefore exactly r in both
cases. The five conditional branches and both returns are locked by static
verification and all targets lie within the complete helper FDE.

When r=0, return hq directly; there is no extra final multiplication. When
r is 1, 2 or 3, define signed byte `sk = input[4q+k]` for values below 128,
and `sk = input[4q+k]-256` otherwise. The fallthrough tail adds
`sum(sk * 256^k, k=0..r-1)` modulo 2^32, multiplies once by M modulo 2^32,
then XORs the product with its logical shift by 24. MOVSBL establishes each
signed contribution; this is not an unsigned little-endian partial word.
The machine adds highest-position bytes first; the Rust ascending loop has
the same sum because wrapping addition is associative and commutative.
Every shift count is 0, 8 or 16. The multiplication/finalizer occurs exactly
once when r is nonzero. For example the one-byte input 0x80 yields
`0xc5cd2b7f`, while empty input yields 397.

Induction over q words and the finite tail cases establishes the hash result
for every admitted slice length, beyond the finite fixture population. No
instruction interpreter, original executable or inferred reference source is
used to compute the frozen expectations.

## Wrapper return

The wrapper saves EDX to EBX, clearing the upper index bits. It calls the
helper with the two descriptor fields and literal seed. Then MOVZX loads
unsigned u16 d, EDX is cleared and DIV ECX divides the 32-bit hash with a zero
high dividend half. With d>0 the quotient fits u32 and the remainder lies in
`[0,d)`. The following EDX self-move preserves its zero extension. The selected
position is `low32(raw_index) + (hash mod d)`, with the sum formed at full
64-bit width. Its maximum is `2^32-1 + 65534`, so the Rust u64 addition cannot
overflow. A checked usize conversion plus slice lookup implements the admitted
read. MOVZX EAX from the selected byte makes the full native RAX equal the
returned u8 value. The stack-only saves/restores are balanced; no data mutation
or hidden callee remains in this wrapper claim.

## Evidence and limitations

The independent oracle was frozen before Rust and folds polynomial byte sums
using Python integer division/modulo, then applies the separate signed-tail
sum. The input-only native client receives descriptors and byte arrays, never
expected values. It exposes both the fixed-seed helper hash and wrapper result,
preventing modulo/table collisions from hiding wrong hash arithmetic.
All 65,536 two-byte tails are covered, along with every 0..256 length, every
byte at each three-byte tail position, multiple word prefixes and seeded
additional cases. Opt0/3 repeated builds agree; real wrong-source runs test
signed tails, word endianness, both shifts, seed/length/block mixing, exact
word endings, divisor width and index extraction. Cases involving the new
refusal variants are separately counted. Passing these fixtures is not
whole-node or compiled-code equivalence. Original type names, application
meaning, other callers of the shared hash helper, pointer ABI and other seeds
remain outside this fixed-seed wrapper contribution.
