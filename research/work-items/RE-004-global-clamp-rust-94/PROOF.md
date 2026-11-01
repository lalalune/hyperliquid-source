# Global clamp and its closed tail-store relation

Target node94 SHA-256 is
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This proof covers the complete 86-byte `[0x55539e0,0x5553a36)` function
and its actual 18-byte tail helper `[0x552fa70,0x552fa82)`. It establishes
three final qword values and full RAX, without assigning application
meaning or recovering a source type for the globals.

## Static closure and storage

The verifier checks the whole 91,774,280-byte target digest, exact bodies,
FDE/CIE records and complete caller. GNU, LLVM and Capstone agree on all
body bytes and instruction boundaries: 20 main instructions, five helper
instructions and 205 caller instructions. The main includes an eight-byte
NOP before its negative branch and has ten following INT3 padding bytes.
The only main external transfer is the tail JMP at `0x5553a23`, whose
actual destination is `0x552fa70`. The helper has no further dependency
and returns at `0x552fa81`. All internal targets are decoded starts.

The two direct E8 candidates `0x54b9c6b` and `0x54b9cc9` are confirmed
calls in the complete 957-byte caller `[0x54b9b60,0x54b9f1d)`. Both return
to ordinary caller instructions; this does not prove application meaning
or exhaust indirect references. The full 80,300-record RELA scan finds no
naming relocation for either function and no relocation overlapping the
retained code or selected globals. No complete helper caller census is
claimed.

The RIP-relative input is the eight-byte `.data` object at `0x57881e0`,
file offset 91,771,360, whose captured bytes are all FF. Its signed initial
value is therefore -1, but runtime writes are possible: the theorem takes
every i64 value, not just that initializer. The three outputs start at
`0x59afc98`, `0x59afca0` and `0x59afca8`. Their complete 24-byte interval
lies in the allocated writable `.bss` section (type SHT_NOBITS), and in
the zero-filled tail of a writable PT_LOAD. That segment has address
91,727,440, file offset 91,715,152, filesz 56,480 and memsz 2,320,432.
The verifier binds both section and segment records, rather than reading
nonexistent `.bss` file bytes or trusting a nearest-symbol label. Initial
zero fill does not imply runtime outputs stay zero.

## Every signed-input path

Let g be the signed qword loaded once from the input. TEST RSI,RSI sets
SF from its high bit and clears OF. JS reaches the negative branch
exactly for g<0. That branch clears both EDI and ESI, zero-extending their
full registers, then jumps to the shared first-store instruction. Thus
its first stored qword is zero and the tail receives RSI=0.

On the nonnegative path MOV instructions preserve the TEST flags.
CMOVLE RSI,RAX therefore selects one exactly when g=0; for g>0 RSI
retains g. Write v=max(g,1). It is in [1,2^63-1], with no overflow or
sign ambiguity. Copying RSI to RDI and logical shifting six bits gives
q=floor(v/64). SHR sets ZF iff q=0, so CMOVE with the constant RDX=1
raises precisely that result to one. CMP against RCX=0x400000 and
unsigned CMOVA cap the result at 0x400000. The first stored word is
therefore min(max(floor(v/64),1),0x400000).

The first store targets `0x59afc98`. LEA then sets RDI to the second
output, leaving RSI unchanged. The tail helper stores zero at [RDI],
clears EAX (zero-extending full RAX), stores the unshifted RSI at
[RDI+8] and returns. Crucially, the last value is v, not the scaled or
capped first word. These instructions also close the previously
unresolved return value: RAX is zero on every path.

The complete relation is:

```
g < 0:   RAX=0; outputs=[0, 0, 0]
g >= 0:  v=max(g,1)
         RAX=0; outputs=[min(max(floor(v/64),1),0x400000), 0, v]
```

For g=0 the result is [1,0,1]. For g=0x10000040 the first word is capped
at 0x400000 while the last remains 0x10000040. Incoming output contents
never affect the result: all three complete disjoint qwords are written.
The source image places input and output in disjoint storage under a
common valid load bias, so no output write can change the sampled input.
Other clobbered registers are outside the projection; notably incoming
RDX survives the negative main path, so no universal RDX constant is
claimed.

## Rust relation and domain

`initialize(i64, &mut [u64;3]) -> u64` models the sampled input and three
output values. Rust first maps negative g to normalized zero; otherwise
it computes max(g,1). It selects the all-zero first word for the negative
case and uses the proved shift/clamp expression otherwise. The remaining
stores and returned zero match the closed helper relation directly.
All casts occur after nonnegativity is established; shifting and clamping
cannot overflow. The complete i64 input domain and every previous state
are admitted. There are no new refusal cases or dependencies.

Correspondence assumes ordinary valid stable input/output memory,
normal instruction/control storage and the stated captured mapping.
This numeric state API does not recreate global storage, runtime load
bias or the original calling convention. Faults, MMIO, concurrent
access, instruction/control aliases, flags, intermediate observations,
timing and unobserved registers are excluded. These restrictions allow
Rust's value projection and do not assert physical access-trace identity.

## Independent expectations and limitations

Before any Rust source existed, the oracle and static record were frozen
with complete input/expected streams. The oracle uses an unbounded
piecewise interval formula: negative, [0,127], [128,0x10000000) and the
capped interval, independently of Rust's normalization/shift/clamp.
It includes 19,267 cases, 9,402 negative values, zero, all values from
-4096 through 4095, neighborhoods of scale/cap/signed-width boundaries,
power-of-two neighbors and deterministic additional values. Previous
states vary independently. There are 5,593 capped outputs.

All four native opt0/opt3 builds/runs match all frozen expected outputs.
Sixteen compiled mutants expose zero normalization, signed classification,
shift width, rounding, lower/upper bounds, narrowed values, omitted stores,
wrong tail values and wrong full RAX. Twenty-five static corruption
controls exercise structural checks separately from the global digest.
Finite runs support the arithmetic proof; they are not a proof by
enumeration of 2^64 inputs. Neither captured code nor an instruction
emulator is executed. Compiled-target identity, whole-node equivalence
and broader global lifecycle behavior remain unclaimed.
