# Complete byte-class relation and full RAX

Target node94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Complete leaf ELF VA `[0x359be70,0x359bebe)`: 78 bytes, 26 instructions. There are no data-memory accesses, outgoing calls or out-of-body branches. No source identity, text encoding or business meaning is inferred from the byte classes.

## All-input relation

Let A=low32(entry RDI), S=low32(entry RSI), and b=A mod 256. MOV EDI,EAX seeds the first result and clears RAX bits32..63. MOVZBL AL,ECX puts b in 0..255, independently of all high bits of A. LEA/CMP checks `(b-192) mod 2^32 <32` unsigned, which for this b domain is exactly 192<=b<=223. This class returns A unchanged.

Every other path eventually executes MOV ESI,EAX, clearing RAX bits32..63. In those paths only SIL can have changed; RSI bits8..63 remain intact until the low32 output is copied. Write S=256H+s, where 0<=H<2^24 and 0<=s<256. The complete return is:

| First low byte b | Complete raw RAX |
| --- | --- |
| 192..223 | A |
| 0, 145..159, 161..191, 224..255 | S |
| 1..143 | 256H + 128 + (s mod16) |
| 144 | 256H + 144 + (s mod16) |
| 160 | 256H + 160 + (s mod32) |

These disjoint classes cover 256 byte values. The signed JLE against143 is safe to interpret numerically because ECX is zero-extended b; it is not a signed-i8 test. The zero case takes the identity path before the nibble rewrite. On three rewrite classes the mask restricts low bits to a range disjoint from the prefix bits, so AND/OR equals the stated arithmetic sum, with no carry into H. In particular the 160 class retains five bits, while 128/144 classes retain four. No first-argument high bit influences class selection; second high24 bits are retained precisely on the second-derived paths. First-derived paths retain all32 A bits. Native incoming argument bits32..63 do not influence RAX.

This proves the complete relation for all 2^64 pairs of u32 values. The 65,536 exhaustive low-byte pairs exercise the finite class/low-result core. Arbitrary upper24 values are covered by the proved separation above, not by claiming that a finite high-bit sample enumerates them. Frozen high-bit witnesses test every position8..31 in each source role, mixed high prefixes, equality/boundary patterns and random u32 values.

## Source and oracle independence

The Rust API `select(first:u32,second:u32)->u64` projects full raw RAX. It matches byte ranges, masks the second value and converts the u32 result to u64. The oracle instead builds an explicitly disjoint/exhaustive partition table and computes results through base-256 quotient/remainder arithmetic. It freezes input and exact expected returns before the Rust directory exists. No Rust output, instruction emulator or captured execution supplies expectations.

The API covers every pair of used argument values without a validity precondition. This is a register-value projection, not a System V function replacement. RSI/RCX/RDX intermediate/final scratch state, flags, timing, native control/stack behavior and instruction faults are unclaimed. The target has no input data reads/stores, so there is no data-pointer, alias, alignment or allocation premise to invent.

## Static closure and caller census

Full artifact authentication precedes section mapping and all 121,299 FDE/3 CIE decoding. The leaf has exactly its complete FDE overlap; both used CIE forms and every complete caller FDE record are bound. Two trailing INT3 bytes are separately retained. GNU and Apple LLVM independently partition every leaf and caller byte identically.

All 113 direct E8 candidates are confirmed at decoded instruction boundaries across 104 complete caller FDEs totaling 84,739 bytes/20,643 instructions. The predecessor had confirmed only 3 of these 113 sites. This packet closes that boundary census without claiming 104 caller algorithms. Combined caller exports preserve complete disassembly with no excerpt gaps. All 80,300 RELA entries are scanned; none names the entry or overlaps bound code. Indirect/computed references remain unenumerated.

No RIP-relative static-data dependency or callee remains inside the selected leaf. No original source/type identity, UTF interpretation, whole-node equivalence, compiled-target-byte identity or progress gate is claimed.

The packet-local overlap index sorts all FDE starts and keeps prefix maxima of ends. For a query [a,b), entries with start>=b cannot overlap; walking preceding entries can stop only when their prefix maximum end<=a. Thus no possible overlap is skipped. Protected relocation intervals use the same criterion: among starts<slot+8, an overlap exists iff the prefix maximum end>slot. An exhaustive-predicate audit covers every bound window and actual relocation destination plus boundaries, and an extra control moves an otherwise unselected FDE onto this leaf. These indexes change lookup cost, not the bound records or predicates.
