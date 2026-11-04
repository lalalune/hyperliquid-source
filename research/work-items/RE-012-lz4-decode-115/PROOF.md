# Logical-byte contract and its premises

This is a manual instruction-backed derivation, not symbolic execution,
execution of captured code, or a whole-source equivalence theorem. Addresses
are linked ELF virtual addresses. `evidence.json` binds each statement's
selected instructions, all branch targets, call slots and complete body bytes.

## State and projection

For adapter `0x477f8c0..0x4780322`, entry arguments are output record RDI,
input pointer RSI, input length RDX and maximum RCX (System V register
observation, not a recovered original Rust type). Inputs point to valid
immutable disjoint storage of the supplied length. After its prefix test,
R13 is the zero-extended little-endian u32 prefix C. No byte swap occurs.
`0x477f8f9` rejects C>maximum using unsigned JB before allocation. An ordinary
successful allocation supplies C writable bytes, alignment1; C=0 uses a
sentinel pointer. Allocation failure does not belong to this theorem.

The private sink at stack+0x40 is (pointer, capacity C, initialized/logical
length); its +0x10 word is stack+0x50. RBP is the running logical output
position, R13 the compressed-block position during decoding, R11 the input+4
base and RDX the compressed length n. At slow-entry `0x477fc00`, or after a
completed slow match at `0x477f9d0`, sink length is set to RBP. Prefix capacity
is not required to equal final length. Native success at `0x477ff73` writes
(C, pointer, min(sink_length,C)). Under the proven bounds the minimum does
not truncate. A final token's low nibble is ignored when literals consume
all remaining input; even token0x0f with C=0 succeeds. An empty block does not.

The projection compares returned byte strings and error *categories*, not
allocation timing, capacity chosen by the replacement allocator, machine
registers, boxed error messages, error payload garbage, padding or addresses.
The five internal decoder categories use tags0..4: output, literal, input,
zero offset, history. The header and over-limit wrappers use different
factories. Rust exposes names, not native discriminants or Result/Vec ABI.

## Slow sequence and error precedence

1. Read a token. Its high nibble is literal count L. High nibble15 adds a
   sequence of bytes, including a final byte<255. The accumulator is u32,
   with carry checked at `0x477fc33`; the base15 addition is u64. Running out
   of bytes is tag2. Overflow goes to panic, not tag2 or a wrapped length.
2. Check L against remaining input at `0x477fc61` before checking remaining
   output at `0x477fc76`. Thus a doubly out-of-bounds literal run is tag1.
3. Copy L literal bytes through helper `0x477e5c0`. Its guards require
   increment<=copy length, no logical+copy overflow and logical+copy<=C.
   Here increment=copy=L. Copies of 1..3, 4..7, 8..16 and17..32 use head/tail
   moves covering the requested interval; larger copies call imported
   `memcpy`. Source and destination are disjoint. At `0x477e67c` the helper
   increments logical length by L. This closes the helper's relevant normal
   byte/length contract, not every invalid-argument panic or libc internals.
4. If input ends here, return success. Otherwise require two offset bytes;
   interpret little-endian u16. Offset0 is tag3 **before** match extension.
5. Match count M is low_nibble+4. Low nibble15 adds a terminated extension
   to base19. Addition at `0x477fd1e` is checked u32; exhaustion is tag2.
6. Check new output length at `0x477fd5d` **before** history subtraction.
   A match both too long and referencing before output gives tag0, not tag4.
   A zero offset still gives tag3 before either of these checks.
7. For D>0 with D<=logical length and enough capacity, each new byte is
   output[current_length-D]. This is a periodic recurrence, not a snapshot
   copy. M>D selects overlap; D=1 uses imported memset. Other overlapping
   matches use bounded 16-byte chunks only when D>=16, then a byte tail
   (`0x477fec6`). For M<=D, source starts at logical-D; checked 32/64-byte
   speculative copies or exact-size memmove implement the same *M-byte*
   prefix under the memory premises below.
8. A completed match requires another token. Reaching input end immediately
   after a match returns tag2 (`0x477f9d5` / `0x477ff94`), not success. A
   following zero-literal token suffices. Thus match-only ending and literal
   ending are deliberately distinct in fixtures and unit tests.

## Fast branch reduction

The native fast branch is selected only if low nibble<15, token<0xf0,
output_position<sat(C-34), and input_position<sat(n-18). Here input_position
points to the token. Therefore L<=14 and4<=M<=18, and:

- after token, L literals and two offset bytes, a following byte remains;
- output_position+L+M<=output_position+32<C;
- neither literal/match extension is needed;
- 16-byte input literal overread and speculative18-byte output copies remain
  inside their declared allocated/input ranges.

It reads/copies16 literal bytes at `0x477fa5a`, advances logical length by
only L, rejects zero offset, and checks output_position+L-D for underflow.
Those failures project to the same category as the scalar specification.
A non-overlap match copies18 bytes but advances by M; an overlapping match
uses the D>=16 vector/byte scheme. Only the M logical bytes are compared.
Uncommitted overcopy bytes cannot affect a subsequent logical byte: any
future literal overwrites its own prefix and every accepted history read
starts in the committed prefix; overlap copies consume bytes committed in
this same match in forward order. Optimized speculative bytes are not
returned or credited as initialized logical output.

The Rust implementation intentionally uses scalar safe recurrence and exact
literal appends. It need not reproduce SIMD scheduling or overcopy side
effects. In particular, this is not a native-memory observational equivalence
claim on errors or unused capacity.

## Memory/helper/exception premises and exclusions

All pointer arithmetic and memory accesses described are over valid ranges;
input length is representable on a 64-bit host. Buffer allocations and
ordinary helper calls return normally and preserve ABI-required registers.
The imported memcpy/memmove/memset operations supply their ordinary requested
byte effects. Native allocator, deallocator, panic, formatting and error-box
bodies are recorded call dependencies, not newly reconstructed here. Sink
non-overlap wide-copy *logical* prefixes use initialized history, but extra
bytes may be uninitialized; their contents and source-language validity are
not established by this packet. The theorem is conditional on normal native
copy completion and does not prove the proprietary program free of UB.

On the Rust side `try_reserve_exact` can return a local Allocation error;
that has no claimed target-error correspondence. ExtensionOverflow reports
the target panic boundary rather than deliberately panicking. Native unwind
call-site entries and landing pads are inventoried, not executed or proven.
No original source layout, full lz4_flex version/fork, original compiler flags,
codec performance, TCP future lifecycle, transitive owner destruction,
source-built node, network compatibility or component gate is established.

## Evidence and oracle independence

`collect.py` authenticates 2,934 complete bytes/677 instructions in two FDEs
using GNU, LLVM and Capstone partitions, plus source Locations/relocations,
PT_LOAD mapping and GNU readelf. These are structural bindings for this
manual proof, not 2,934 reconstructed-byte matches. The TCP call binding was
already established in #2076 and is explicitly credited context.

Before Rust existed, `corpus.py` fixed the input/expectation hashes. Of158,486
cases,7,334 have separately constructed outputs or explicit boundary outcomes;
constructed matches expand a source period mathematically without calling
the decoder oracle. Remaining expected outcomes come from the instruction-
derived Python contract; they are not native execution results. The Rust
uses append-by-byte history while the construction/oracle uses period
expansion. Successful corpus checks support implementation consistency with
this specification; finite sampling does not prove the manual reduction.

The 42 individual native-clause corruptions test rejection below the full
capture hash, not changed target execution. Compiled production mutations
exercise the actual Rust comparator and have separate mismatch denominators.
