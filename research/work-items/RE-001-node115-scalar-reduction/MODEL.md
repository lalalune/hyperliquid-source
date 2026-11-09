# Static model and trust boundary

`analyze.py` admits the complete target before parsing or producing output.
Pyelftools supplies ELF, section/segment, relocation and CFI decoding; Capstone
supplies instruction operands. GNU independently checks every instruction's
start, bytes and mnemonic, and both FDE extents. The operand semantics remain
an explicit model, not a second independent disassembler semantics proof.

Each 64-bit input qword is a symbolic bitvector. Its bytes are the actual
little-endian memory representation, whereas the 32 input bytes are interpreted
as one big-endian scalar. Input, output, stack and optional flag destination are
abstract, valid, pairwise disjoint regions. The flag pointer has two cases:
null, or a nonnull pointer to four writable bytes. Input/output are never null.
Ordinary System V AMD64 register widths and calling convention are assumed.
No host or target address is dereferenced by the model.

The model constructs expressions by iterating the finite decoded instruction
list. It has no emulator, process loader, executable memory or target process.
It accepts only the observed instructions; unknown opcodes, memory regions,
widths or symbolic control flow fail. Reads must name initialized slots. It
models the two PUSHes/POPs and verifies all six callee-saved GPRs and the final
stack pointer. The sole branch is the resolved optional-flag-pointer test;
its taken edge must target the recorded POP instruction.

MOV preserves flags; 32-bit register writes zero-extend and byte writes preserve
the upper bits. MOVZX zero-extends, MOVSXD sign-extends, BSWAP reverses eight
bytes, LEA does wrapping arithmetic without changing flags. ADD/ADC compute
carry with a width-plus-one sum. CMP uses unsigned borrow and equality; SETcc
reads those flags. AND/OR/XOR/TEST clear CF and set ZF. NOT preserves flags;
NEG sets CF iff its input is nonzero. SAR is signed and masks its shift count.
Its carry is marked undefined because it is overwritten before a live use;
undefined live flags fail. The decoded transfers preserve all intermediate
fixed-width wrapping, partial-register writes and carry propagation.

Z3 searches for any disagreement between these expressions and the separate
256-bit specification `x >= n ? x-n : x`, with flag `x >= n`. Each query has a
60-second limit. SAT, UNKNOWN and timeout reject a positive theorem. Seven
positive queries are UNSAT. This establishes claims under the model, not actual
captured-code execution or formal verification of the Rust compiler/library.
The additional range query and `2*n > 2^256-1` justify a single subtraction as
arbitrary-precision modulo for every input.

The integer boundary oracle uses Python's arbitrary-precision `% n`; it does
not reproduce the captured carry algorithm. Rust uses a separate four-limb
borrow chain. Its test corpus is the frozen instruction-expression output,
independently checked with that integer oracle. Native source tests are finite
coverage, not an all-input proof of the compiled Rust artifact.

Excluded: aliasing/overlap and faults, enclosing object types, memory allocation,
callbacks, signature validity or elliptic-curve operations, caller invariants,
exact original library/version/build, timing and side channels, unwind metadata
semantics, asynchronous interruptions and whole-program equivalence. The helpers
have no calls or code relocations; no external helper summary is assumed.
