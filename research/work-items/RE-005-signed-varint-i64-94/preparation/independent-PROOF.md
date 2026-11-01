# Independent normal signed64 wire/value/error/cursor relation

Target node94 is 91,774,280 bytes, SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The primary complete FDE is ELF VA `0x4b6fa60..0x4b6fbc5`, 357 bytes / 99
instructions, body SHA256
`d22b30b24c723356b830ec168251b150e482ceec091c5ebc05b4f40f1afbba4f`.
`NATIVE-REVIEW.json` independently binds actual full-target bytes, indexed
FDE/CIE, executable mapping, every instruction partition, both jump tables,
both typed GOT bindings, and all 80,300 actual RELA records. No relocation
patches selected code or tables. Supporting, previously established unsigned
Reader316 (`0x466d980..0x466dabc`) and error-builder14
(`0x466dac0..0x466dace`) total 330 bytes / 100 instructions. They are separate
dependency denominators, not new signed implementations or newly recovered
bytes. No inferred/original Rust implementation was read for this proof.

## Domain and active observation

Input is a valid immutable readable byte slice with pointer P, byte length L,
L <= isize::MAX, valid nonwrapping pointer arithmetic, a writable two-word
cursor `(P,L)`, and a separated valid output/stack/code/data allocation. DL is
an arbitrary raw byte e: zero chooses little endian; every nonzero value
chooses big endian. This is a raw machine-entry contract, not a claim about
the original nominal configuration type or which e values all callers use.
The observed actual caller passes DL0; enclosing caller semantics are excluded.
No outer mode/limit/counter budget is supplied or inferred for this function.

The projection contains raw tag, signed value and its 64-bit pattern for tag18,
additional required bytes for tag0, and expected/found raw code bytes for tag3,
plus consumed bytes and the entire residual slice. Every other result field
is null because it is outside this projection. Null never means a native byte
was unwritten or zero. The error path copies stack-derived inactive bytes at
`0x4b6fba7..0x4b6fbc0`; those values must not be invented, normalized to zero,
or claimed unchanged. Native output-pointer identity, nominal enum ABI, padding,
hidden registers, frames, aliases, concurrency, fault/unwind behavior and whole
codec/node identity are excluded from the safe implementation claim.

## Unsigned payload relation and dispatch split

The primary compares L with8 at `0x4b6fa6c`; L>8 takes its own fast path,
and L<=8 calls the actual unsigned Reader316 through slot `0x57745e0`.
Let the first byte be t. Values t<251 are their own unsigned payload and
consume1. Markers FB/FC/FD select payload widths2/4/8 and total widths3/5/9.
Payload value is the base256 polynomial in the selected byte order; arbitrary
nonminimal encodings are admitted because no minimality check exists. The
ROL/BSWAP plus DL test/select sequences implement exactly that polynomial.
U16/U32 loads zero-extend; all unsigned results are in0..2^64-1.

The fast table at0x706714 has exactly FB->faac, FC->fae1, FD->faca,
FE->fb30 within the primary body. L>8 guarantees every admitted payload fits.
On success, P advances by its total width and L decreases by that width.
FE and FF instead construct tag3 through slot0x57745e8 with raw expected2
and raw found4/12 respectively. Those fast errors do not store the cursor:
they consume0 and retain the entire input.

The unsigned Reader's actual table at0x6f6ed8 maps FB/FC/FD/FE to
0x466d9e7/0x466da01/0x466d9f4/0x466da8c. Its complete body proves:

* Empty input returns tag0/additional1 and consumes0.
* Nonempty input consumes its tag first, before any marker classification.
* FB/FC/FD with L below3/5/9 return tag0/additional(total-L), retaining that
  consumed tag. With sufficient bytes, consume the total and return unsigned
  payload tag18. The FD success arm is unreachable through this primary's
  L<=8 call gate, but the supporting helper's complete contract is retained.
* FE/FF return tag3 with raw expected3 and found4/12, consuming1.

No supporting normal path returns any tag outside0/3/18. Fixed slots and
the error builder's complete stores establish those exact code bytes, without
opaque callback contracts. No source-language error-name assumption is needed.

## Signed mapping for all unsigned64 values

For u in0..2^64-1 write u=2q+r, with r in{0,1} and q<=2^63-1.
The native sequence `SHR1; AND1; NEG; XOR` at0x4b6fb02..0x4b6fb0e returns
the two's-complement word `q XOR (0-r)`. For r=0 it is q. For r=1 it is
the complement of q, whose signed interpretation is -(q+1). Thus the full
mathematical signed result is

    f(2q) = q; f(2q+1) = -(q+1).

This is a bijection onto[-2^63,2^63-1]. In particular u=2^64-2 gives signed
MAX and u=2^64-1 gives signed MIN. A safe bitwise reconstruction can cast
u>>1 to i64 (always representable), negate only the bit0 value0/1, then XOR.
It never needs signed negation of MIN or an overflowing signed addition.
The oracle instead uses the piecewise integer formula, independently of that
proposed implementation expression. Exact bits are s for s>=0 and2^64+s
otherwise. The primary stores that word at output+8 and raw tag18 at output0.

## Error transformation and complete normal partition

After either helper call, tag18 rejoins the exact signed transform. Other
tags are forwarded; only tag3 changes its two code bytes. At
0x4b6fb75..0x4b6fba2 each byte c becomes c+6 when unsigned c<6 and remains
c otherwise. For c<6, c+6<=11, so the byte conversion cannot overflow.
Consequently reachable type errors are:

| Entry residual length | Marker | Raw tag | Expected | Found | Consumed |
| --- | --- | --- | --- | --- | --- |
| L>8 | FE | 3 | 8 | 10 | 0 |
| L>8 | FF | 3 | 8 | 12 | 0 |
| 1<=L<=8 | FE | 3 | 9 | 10 | 1 |
| 1<=L<=8 | FF | 3 | 9 | 12 | 1 |

Tag0 shortages preserve their exact helper additional count and cursor. Other
normal tags and arbitrary error-code bytes cannot arise from these fixed
helpers. Inactive copying supplies no extra defined observation. All primary
branches are covered by L>8/L<=8, t<251/FB/FC/FD/FE/FF, endian0/nonzero,
success/error tag and the observed unsigned code comparisons. Valid slice
bounds guarantee every read and cursor advance fits; helpers terminate and
no loop exists in the primary. This closes the complete normal relation.

Repeated calls apply the relation to the remaining slice, without a halt flag
or automatic error skip. A fast FE/FF can repeat indefinitely with zero
consumption; bounded call stimuli expose that. A slow type error consumes its
tag so the next call may decode following bytes. Success can cross the L=8
dispatch threshold. Empty calls continue to return additional1.

## Independent pre-source authority

The mathematical oracle consumes high-level byte-symbol sequences and raw
endian bytes, using integer inequalities, base256 polynomials and the piecewise
signed formula. A separate serializer emits the four raw client fields:
`id|rawDL|lowercasehex|calls`. Canonical sorted-key compact JSONL contains one
record per bounded call, indices1..calls, all active fields and full residual
bytes. No semantic role, expected value or plan is supplied to Rust. Finite
cases corroborate this structural all-domain proof; they are not native
executions or an exhaustive population of all strings/values. Existing occupied
u8/bool1454, raw Reader1325 and outer-wrapper1365 scopes are not reimplemented
as claimed new recovery. New proof/code is MIT; captured evidence keeps its
original rights. No gate or new target-byte identity is claimed.
