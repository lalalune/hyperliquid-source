# Store-before-table-load correspondence

This proof binds the complete node94 leaf `[0x54ccfb0, 0x54cd009)`, 89 bytes
and 24 instructions, to the full target digest in `static.json`. Its three
conditional branches and one unconditional branch stay within the body;
it has no call, one return and one optional data store.

## Scalar observations and memory order

Let O be the entry object pointer, B the entry RSI value, I the low32 bits
of entry RDX, and P the optional entry RCX output pointer. The entry copies
B into RAX before any data access. The function chooses a selector s:

1. If O=0, s=0 and no object field is read.
2. If O!=0 but the qword at O+0x90 is zero, s=0 and no selector byte is read.
3. Otherwise s is the unsigned byte at O+0xa1+I.

Both paths execute a 32-bit EDX move before the table access, so incoming
bits 32..63 of RDX are discarded on every path. A selector is in 0..255.
The LEA/subtract/shift sequence computes `(8*s-s)*32 = 224*s`, whose
maximum 57,120 fits in u64 without overflow. Zero paths clear this term.

If P!=0, the function stores the zero-extended selector as a little-endian
four-byte word at P. If P=0, it performs no store. It then computes the table
base from RIP-relative LEA and reads a four-byte word at T+4*I. This read is
**after** the optional store. MOV into R9D zeroes its high bits, so even an
entry with bit31 set contributes its unsigned u32 value. The final result is

```text
RAX = (B + zero_extend(table_word_after_store) + 224*s) modulo 2^64.
```

Both ADD instructions use 64-bit wrapping arithmetic and no later branch
consumes their flags. The complete RAX is returned. Object fields and the
selector have already been read before the output store; if the output aliases
those fields, their new contents do not change s. If it overlaps any of the
selected table's four bytes, those updated bytes do change the loaded entry.
Partial overlaps at either end matter as well as exact coincidence.

For exact output/table coincidence, the loaded entry equals s and the return
is `(B+225*s) mod 2^64`. With B=10, s=7 and an initial entry 0xfedcba98, the
result is 1585. A table snapshot taken before the store would give a different
result. The Rust reads `entry` only after copying all four output bytes.

## Table mapping and load bias

The instruction at 0x54ccff7 has bytes `48 8d 0d c2 cc 2c 00`. Its next
linked VA 0x54ccffe plus signed displacement 0x2cccc2 is 0x5799cc0. This linked
address lies in allocated writable NOBITS `.bss` and a writable PT_LOAD
memory extent. There are no file bytes to use as initialized table values.
The number of table entries and runtime initialization remain unknown.

`table_base` is an explicit runtime address in the image API. Correspondence
requires it to equal the original LEA result, namely the actual image load
bias plus linked VA 0x5799cc0. No zero load bias or virtual-address mapping is
inferred. The parameter permits translating the symbolic data image while
preserving alias relations; it does not claim that the target takes an extra
argument. The selected table word must be mapped by the supplied image even
when O or P is null. A null object does not skip the table lookup.

## Safe single-image API

Image byte j denotes address image_base+j. The last mapped byte must fit u64;
an image ending exactly at u64::MAX is valid. An empty image has no mapped
bytes. Access admission uses address subtraction, checked usize conversion,
checked range endpoints and the supplied slice length. All field additions
must be nonwrapping. I<=2^32−1 makes 4*I at most 2^34−4, so that multiplication
fits u64; adding it to an arbitrary runtime T is checked.

The function reads the presence/selector needed for its selected path, then
checks the optional output interval and table interval before any store.
After admission, the write and table read occur in native order. Required
fields and every accessed table/output byte must lie within the image;
unused selector fields are not demanded by zero paths. All other bytes remain
unchanged. There is no restriction that output, state and table be disjoint.
Their overlap is represented by one mutable byte slice, without unsafe or
aliased mutable Rust references.

`ImageRange`, `StateBounds`, `OutputBounds` and `TableBounds` are new safe
refusals. Each leaves the complete image unchanged. They are not original
error returns: a native table fault can happen after the output store. Atomic
refusal is deliberately additional policy, separately counted in validation.
The native relation covers successful paths through valid ordinary memory,
stable except for this function's own write. It assumes unchanged code and
ordinary return-stack/control behavior. Faults, self-modifying code, output
overwrites of control state, volatile/MMIO effects, external concurrent
mutation/observation and wrapping address accesses are excluded.

Every Rust index is guarded by its admitted span; converting fixed-width
sub-slices to arrays cannot fail. The function has no unbounded loop. B and
the returned numeric address may wrap because the body only computes that
value; it never dereferences the returned address. The API does not invent
a validity check for the returned pointer-shaped value or name its purpose.

## Independent immutable overlay oracle

The oracle was frozen before Rust. It derives s from the immutable entry
image. For every byte position j, it defines the final byte independently:
if j is in the optional output interval, use byte j−P of the zero-extended
selector; otherwise use the entry byte. The table value is a base256 digit
sum over four such final bytes. This is a closed per-byte overlay relation,
not sequential stores, Rust execution or a decoded-instruction interpreter.

The same independent image is returned on safe refusal, permitting full-byte
atomicity checks. Fixtures cover every selector value, all seven partial/exact
table overlaps, output aliases with state fields, null object/output, high
index bits, unsigned entries, wrapping numeric results, exact endpoints and
missing ranges. Finite coverage corroborates the general overlay proof; it
does not enumerate every possible image or original runtime object.

## Static caller scope

Complete GNU/LLVM/Capstone decodes agree on the leaf and all three caller
FDEs. Six standalone LOCK prefix rows in LLVM caller exports are joined only
after validating the exact F0 byte and adjacent address; raw exports remain
unchanged. Whole-text E8 scanning finds sites 0x55557a3, 0x5556447 and 0x555755c,
each confirmed at a full caller instruction boundary. The complete FDE/CIE
records, seven following INT3 bytes, table LEA and NOBITS memory mapping are
retained. All 80,300 RELA records are checked for naming and protected-code
writes, with none found. This is not a complete indirect-reference census,
caller reconstruction, table-length proof or component-completion claim.
