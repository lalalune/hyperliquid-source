# Modular inverse scaling and complete state relation

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
complete ELF VA body `[0x4ea41e0,0x4ea4216)`. This proof concerns the full u64
numeric relation, the sole cursor-field write and full returned RAX. It does
not identify an original container, element type or source-level function.

## Instruction closure and projection

The 54-byte body contains 14 instructions and a single final return, with no
branch, call or RIP-relative data read. Exact FDE/CIE records and the ten INT3
bytes after the body are bound; the next FDE starts at 0x4ea4220. The whole-text
E8 scan finds no direct entry candidate. The full RELA scan binds one symbol-zero
R_X86_64_RELATIVE entry at slot 0x574faf8, whose eight original bytes are zero.
Applying that relocation yields load_bias+entry. Slot membership does not prove
a vtable or callback signature, and no complete indirect-caller census is claimed.
Neighboring cluster functions are outside this contribution.

Let C and E be the entry qwords at RDI+8 and RDI+24, and R the full entry RSI.
Both field loads precede the only store. Under ordinary stable readable/writable
memory and nonwrapping valid field addresses these distinct eight-byte fields
do not overlap. Therefore supplying end as a copied u64 and cursor as a mutable
u64 preserves the field-value relation. No other original object byte changes.
The API reconstructs no pointer ABI, flags or scratch registers. Faults, code/
control aliases, concurrency and MMIO effects are outside this state projection.
There is no numeric restriction on C, E or R; even invalid-looking addresses
are treated as integers because the function never dereferences their values.

Let B=2^64 and F=0x2e8ba2e8ba2e8ba3. The SUB and logical SHR produce
`n=((E-C) mod B) div 8`, hence `0 <= n < 2^61`. The two-register IMUL retains
only the low 64 product bits, so `s=(n*F) mod B`; its signed mnemonic does not
change those bits. CMP/CMOVB selects `t=min_unsigned(R,s)`. The second IMUL
and ADD store `C'=(C+88*t) mod B` at RDI+8. The final SUB returns `R'=R-t` in
full RAX. Since t<=R this subtraction does not underflow, though the source
states wrapping arithmetic consistently. All other arithmetic that may overflow
is explicitly wrapping in Rust. The mutable cursor write and returned remainder
therefore agree for all 2^192 input triples without an assumed span invariant.

## What the constant establishes

Direct integer multiplication gives `11*F = 2*B+1`; thus F is the multiplicative
inverse of 11 modulo B. Because 11 and B are coprime, for every n there is exactly
one s in `[0,B)` satisfying `11*s == n (mod B)`. This arithmetic identity is
established from the constant. The reason the original caller chose this layout
or stride remains unknown; no source type or validity invariant follows.

A different way to compute s, used by the independent oracle, is to find k in
`0..10` such that n+kB is divisible by 11. Since B mod11=5 and 5*9 mod11=1,
`k=(-9*n) mod11` is that unique choice. Then `s=(n+kB)/11` is an exact integer
quotient, lies below B, and satisfies the same congruence. This does not perform
the source's low-word product or reuse the factor in its calculation.

## Conditional ordinary division, and why it is not the general rule

If E>=C and E-C=88*m as ordinary nonnegative integers, then
`n=(88*m)/8=11*m`. Since m<B, the modular inverse returns s=m exactly. The
state transition then advances by `min(R,m)` elements and returns the leftover
request, without cursor overflow or passing E. This is a theorem conditional
on the stated numerical premise; it is not an assertion that all callers obey it.

The low three span bits (remainder 0..7) are discarded before scaling. If n is not divisible by 11, ordinary floor division is generally wrong.
For example C=0, E=8 gives n=1 and s=F, not zero. A request of one then stores
cursor 88 and returns zero, even though that cursor exceeds E. Adding a generic
end clamp would change the target's behavior on these inputs. Reversed/wrapped
spans likewise retain modular subtraction, logical shift, inverse multiplication
and cursor wrap. No special error or normalization is invented for them.

## Independent evidence and limits

The quotient-equation oracle was frozen before Rust existed. Its corpus covers
all 11 count residues, all eight discarded low-span-bit values, high-bit and
wrapped-span boundaries, request values immediately around the modular threshold,
explicit ordinary 88-byte spans and seeded u64 triples. Canonical cases are
additionally checked against ordinary element-count division in Python, without
feeding that expected answer to the native client. The Rust client receives
only C/E/R and emits the new cursor and full remainder, with no normalization.

Native wrong-source controls test ordinary division, signed clamp/shift,
saturation, product-half selection, count truncation, constants, stride, store
and return. A division-only mutant can pass canonical-span cases while failing
the general domain; those counts are reported separately. Repeated opt0/3
artifacts and exact outputs support the new implementation. The algebra above
establishes the full-domain relation beyond the finite native corpus. Neither
is original machine-code equality, caller reconstruction or whole-node recovery.
