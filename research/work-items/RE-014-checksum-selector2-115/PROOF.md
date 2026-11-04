# Manual source correspondence and explicit premises

This is a manual arithmetic/control-flow argument, not a machine-checked proof
of LLVM or whole-node behavior. Actual own-code tests are separately measured.

## Original identity and selected use

The leaf418bytes and wrapper177bytes are each checked against full body SHA,
actual FDE ranges, raw FDE/CIE records and the complete target SHA. Exports use
ELF virtual addresses and no masks. The wrapper's DIL2 route sets RSI from
its saved original length, RDI from its saved original buffer, zeroes EDX and
restores its saved stack/registers before tail-jumping to61da8b0. No other helper
runs on this selected route. This does not close the other raw-selector arms.

## Word transfers and arithmetic

All checksum arithmetic is modulo2^32. Different native copies of each prime,
rotation and final shift are read at their own instruction operands. The
recorded certificates check that all copies agree, that initial lanes are
seed+P1+P2,seed+P2,seed,seed-P1, and that the rotations/avalanche have the
observed shapes. No upstream source version is inferred from these identities.

For nonnull storage require a valid initialized, immutable allocation of L
bytes, L<=isize::MAX and no address wrap. No alignment premise is added.
For L>=16, the native loop first consumes one stripe and continues while
cursor<P+L-15. After k stripes cursor=P+16k, so continuation is equivalent to
16(k+1)<=L. It therefore processes exactly floor(L/16) stripes. The Rust loop
uses L-offset>=16 and enumerates the same four little-endian words in order.
Both apply (lane+word*P2), rotate13 and multiplyP1 to each lane modulo2^32.

The native lane rotations1,7,12 and right14 (=left18), their sum and the
low32 length addition agree with the source's wrapping expression. For L<16
the initial value is seed+P5; length is added on that route instead. Thus both
routes include length exactly once, truncated to32bits, even though indexing
and the large-stripe comparison use full64-bit length.

The remaining length is below16. The native unrolled word stages therefore
consume exactly floor(remainder/4) words (at most3), matching the Rust loop.
The right15/left17 rotations and P3/P4 values match at each stage. The final
0..3 bytes are consumed in the same order using P5,left11,P1. Both finishes
use xor>>15,*P2,xor>>13,*P3,xor>>16. Every native final EAX operation zeroes
upper RAX, which the own-code comparator checks explicitly.

For a null pointer, the actual native JE reaches the final avalanche before
any length addition or storage access. The source returns from the same
seed+P5 avalanche before pointer arithmetic. Consequently all raw null lengths
have the empty-input value, without dereferencing null or imposing a new rule.

## Rust storage and machine boundary

At every stripe load offset+16<=L; at every word-tail load offset+4<=L;
at every byte load offset<L. Offsets only increase within L, so the stated
length/allocation bound also justifies pointer arithmetic without usize overflow.
read_unaligned avoids introducing a reference-alignment obligation absent from
ordinary native loads. Valid pointer provenance, immutability and absence of
concurrent data races remain caller premises, not consequences of integer tests.

Only the newly built known ELFREL section is decoded into the bounded evaluator.
It rejects captured ELF images, text relocations, extra text/helper calls and
external memory; RAM reads require initialization and a finite step bound.
The ROL extension is scoped to observed32-bit immediate counts. Its carry is
the result's low bit; count1 overflow is high-bit xor carry; other overflow
remains unknown; SF/ZF are preserved. Independent bit-string tests check this
architecture contract. Callee-saved registers are seeded with synthetic values
and checked after each own-code return. No original instruction stream runs.

The manual argument connects source recurrences to observed native transfers.
The finite compiled-code corpus and compiled/native corruption controls test
that bridge; they are not a formal compiler verification, arbitrary-invalid-
memory guarantee or claim about omitted caller/selector/streaming behavior.
