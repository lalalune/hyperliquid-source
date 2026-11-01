# Full-byte-domain mixed-width lookup pair

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The two complete FDEs are `[0x299e280,0x299e29e)` and
`[0x29d7fc0,0x29d7fde)`, 30 bytes/seven instructions each. They share the
same instruction pattern and differ in two RIP displacements. Both actual
bodies are independently bound; sharing the source algorithm does not assume
that a label or byte resemblance proves their behavior.

## Full register-input and numeric-data relation

For member 0, let A=`0x3f7918`, B=`0x3f7ba0`; for member 1, let
A=`0x4024a0`, B=`0x402728`. Let L be the actual ELF load bias, and I be the
incoming full u64 RDI. Define j=`I mod 256`. The instruction at entry+7
is `movzbl %dil,%ecx`: it removes all high input bits and makes full RCX
exactly j. It is neither a signed byte nor a u32/full-register index.

The first LEA computes A+L modulo 2^64. `mov (%rax,%rcx,8),%rdx` reads
exactly the eight bytes at A+L+8j, interpreted as an unsigned little-endian
qword. It replaces all 64 bits of RDX. The second LEA computes B+L;
`movslq (%rsi,%rcx,4),%rax` reads exactly four bytes at B+L+4j and
sign-extends their i32 value to full RAX. The ADD then gives

```
RDX = u64_le(original bytes[A+8j .. A+8j+8])
RAX = (L + B + signed32(original bytes[B+4j .. B+4j+4])) mod 2^64
```

The final RET does not change either data register. No helper, branch,
conditional memory access, second dereference, output store or external
import is involved. The loaded qword and returned numeric address remain
opaque: no string identity, pointer target validity or returned-value type
is inferred from data resembling lengths, text or addresses.

Both LEA and ADD are modulo64 operations. The sign-extended offset lies
in `[-2^31,2^31-1]`; converting it to u64 gives the same modulo64 residue.
Rust uses `i64::from(i32)` before that cast, then explicit wrapping adds.
Neither debug overflow checking nor optimizer assumptions can change the
result. RDX is independent of load bias because its captured source bytes
have no overlapping relocation; treating the qword itself as a relocated
pointer would be incorrect.

## All reachable bytes, including overlap

j ranges over exactly 0..255. Every qword access is contained in
`[A,A+2048)`, and their union is precisely that full interval. Every signed
offset access is contained in `[B,B+1024)`. In both members B=A+0x288,
so the latter interval is `[A+0x288,A+0x688)`, wholly inside the qword
window. The overlap is actual shared physical data, not two independently
invented tables. Neither the 256-element reachable window nor the base
spacing establishes a source-level logical table extent or enum domain.

`data0.bin` and `data1.bin` preserve all 4,096 unique bytes. Static checks
compare them to target bytes and fixed hashes, bind the section/PT_LOAD
mappings, and derive all 256 unsigned qwords and 256 signed offsets from
each window. Both windows are in read-only `.rodata`. A scan of all 80,300
RELA entries checks full eight-byte writer overlap, including partial
writes spanning either endpoint. There are no overlapping relocations
of any present type, so no partially relocated shared bytes are ignored.
The verifier rejects unreviewed relocation kinds or REL sections.

The two signed-offset ranges actually observed are
`[-2045568,2037672306]` and `[-2089480,2037540213]`; both signs occur.
For example, each member's index 5 resolves to linked address `0x20bfa0`,
while index 0 resolves to `0x3f7520` or `0x4019b1`, respectively. These
are numeric examples only, not evidence of pointed-to object identity.

`tables.rs` contains scalar numeric values recovered from those raw data
bytes, not instructions, inferred source text or a transplanted executable.
Its two typed arrays per member preserve the same overlap by value:
the independently decoded byte windows feed the frozen expectations, while
the compiled constants feed actual native lookups. Every byte index is
exercised in the native comparison, including the overlapping region and
the part beyond the signed-offset window. The library cannot dynamically
modify either constant array.

## API, totality and original normal-return domain

`lookup(Member, index_bits, load_bias)` is a new safe value API.
The `Member` selector chooses which entrypoint to project; it is not an
original argument. All u64 index/bias inputs are admitted. Index extraction
yields a usize no greater than 255 on every Rust target, and both arrays
have 256 entries. Every indexing operation is therefore in bounds. There
is no unsafe code, allocation, fallible operation, data-dependent panic,
saturating arithmetic or input cap.

The returned `Registers` has the full RAX/RDX pair. RCX, RSI, flags,
stack/control behavior and the machine ABI are not projected. The source
performs safe constant accesses; it does not dereference the numeric
returned address or turn captured addresses into Rust pointers.

For correspondence, original runtime bytes throughout the selected reads
must equal these immutable captured `.rodata` bytes, L must be the actual
module load bias, and both original reads and return must complete normally.
The original accesses are ordered qword first, signed offset second. Under
the immutable ordinary-memory premise their values are independent of
interleaving and of the physical window overlap. The API makes no claim
for runtime-patched bytes, concurrent mutation, MMIO, page faults,
noncanonical addresses, wraparound mappings or code/control aliases.

Arbitrary mathematical load biases are useful for checking modulo64 output,
but may not be realizable module mappings. Totality of the numeric Rust
API does not assert original machine normal returns for such artificial
biases. No mutable-image API or dynamic loader is reconstructed here.
These explicit limits preserve both full-u64 arithmetic and the actual
runtime-memory premise without inventing private source types.

## Full bodies and caller context

The two FDE/CIE records, full bodies, two following INT3 bytes per member,
address successors and section-order neighbor are bound. The address
successor of member 1 is itself its retained caller. GNU and Capstone
agree on complete body/caller instruction boundaries. LLVM agrees on all
leaf boundaries; in caller 1 alone it displays LOCK separately at
`0x167aa04` (`f0`), then DEC at `0x167aa05` (`48ff08`). The verifier checks
those exact two raw rows and joins their **display boundary only** to match
GNU/Capstone's `f048ff08` instruction. No byte or operand is masked.
The initial strict-boundary verifier and its failure trace are retained.

The full four caller FDEs span 15,600 bytes and 3,161 GNU/Capstone instruction
boundaries. Seven E8 candidates are confirmed instructions: six target
member 0, one targets member 1. The full `.text` E8/E9 scan finds exactly
those E8 candidates and no E9 candidate for either entry. No RELA record
names either entry or overlaps either body, following padding or caller.
This closes the retained call sites; it is not a complete indirect-reference
census or reconstruction of caller semantics, exception tables, provenance,
input categories or downstream interpretation. Caller LSDA references are
reported by the FDE parser but their wider behavior is not a leaf dependency.

## Independent expectations and qualification

All inputs, outputs, raw data and static evidence were hash-frozen before
any Rust directory existed. The oracle forms unsigned values from raw-byte
polynomials, applies explicit two's-complement subtraction for negative
four-byte values, and evaluates one unbounded address expression modulo64.
Rust uses compiled typed scalar arrays, i32-to-i64 widening and staged
wrapping operations. The native client reads only member/index/bias inputs;
it never receives expected outputs or imports the oracle.

Every member/index pair is covered, including ignored upper register bits,
both offset signs, high qword bits and biases selected to yield zero, one
and `u64::MAX` after address wrapping. Expected outputs contain both full
u64 registers with no masks. Real compiled mutants alter index width/order,
member data selection, signedness, byte order, base constants, address
arithmetic and returned widths. Comparator corruption checks, optimization
profiles and raw repeated-build comparisons qualify the new code path.

This proves the bounded relation for the full specified input domain under
the immutable-runtime-byte premise. Finite native experiments qualify the
implementation and harness; they do not execute the captured instructions,
prove original compilation identity or establish whole-node equivalence.
