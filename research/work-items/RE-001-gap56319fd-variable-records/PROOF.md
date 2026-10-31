# Conditional static proof: candidate 0x56319fd record transfers and batch bounds

This is a fixed-artifact static transfer and conditional arithmetic proof. It
is not a Rust implementation, source/ABI attribution, observed runtime-table
validity, caller-reachability, equivalence or progress-gate claim. The producer
binds all 324 decoded rows to the source bytes and six finite symbolic phases.

Target node #94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Freshly admitted original span `[0x56319fd,0x5631ef2)` is 1,269 bytes,
324 native instructions, SHA-256
`00933a9b47d97b4ac90e7845469b6a4b0e3d76357432bf6e86f65d7bd215c425`.
The preceding 1,149-byte candidate and PR #1022 remain unchanged.

## 1. Observable difference and used record fields

Let Q denote physical entry RDI. The state loads map the four input cursor
words into R8/R9/R10/R11, output cursors into RSI/RBX/RCX/RDI, four shifting
words into RBP/RDX/R12/R13, and a runtime table address T into R14 from Q+60.
This describes physical use, without inferring an original source type.

For each lane, five unrolled groups perform these actual transfers:

```
k = word >>u 53                       # 0..2047
payload = load16(T + 4*k)             # bytes 0 and 1
shift = zero_extend(load8(T + 4*k+2)) # byte 2
advance = zero_extend(load8(T+4*k+3))  # byte 3
store16(output, payload)
word = SHLX64(word, shift)            # count masked to six bits
output = output + advance            # 64-bit modular ADD
```

There are twenty actual WORD stores: five per lane, forty byte-write events
per executed inner body, with potentially overlapping addresses.
The twenty payload/shift/advance load groups are separately present in the
original bytes. Each store always writes two bytes even when its advance is
one or zero. The table-relative read envelope is 8 KiB, not #1022's 4 KiB.

Thus a logical cursor advance does not equal the physical store width.
For advance 1, a store can write one byte beyond the resulting logical cursor;
the following store may overwrite it. A reconstruction that writes only the
advance-byte count would omit that observed physical side effect. Runtime
table contents and their producer have not been recovered.

## 2. Exact stored bound operands

At working RSP W = entry_RSP - 184, the original prologue preserves:

| W offset | Captured value | Use in outer arithmetic |
| --- | --- | --- |
| 08 | initial output 1 (entry Q+28) | E0 minus current output 0 |
| 10 | initial output 2 (entry Q+30) | E1 minus current output 1 |
| 18 | initial output 3 (entry Q+38) | E2 minus current output 2 |
| 20 | entry Q+70 | E3 minus current output 3 |
| 28 | entry Q+68 | L subtracted from input cursor 0 |
| 30 | initially a duplicate Q, later the loop stop | mutable stop scratch |
| 38 | Q | protected state base recovered before return writes |

The table uses hexadecimal offsets. W+00 is scratch: first RDX's bit word,
then saved R8 while R8 carries table payloads, then the next outer spill.
The E values are fixed from the initial frame, not the next lane's current
cursor after progress. Their interpretation as accessible-region ends is an
explicit condition below; the code does not establish that allocation fact.

Write `u(x)` for reduction modulo N=2^64. Each outer evaluation computes:

```
d = u(I0-L)
rj = u(Ej-Oj) for j=0..3
r = unsigned_min(r0,r1,r2,r3)
q = unsigned_min(floor(d/7), floor(r/10))
stop = u(O3 + 5*q)
```

The source SUB/CMOVA chain at 0x5631a97..0x5631ac8 selects all four remainders.
No output ordering/lower-bound validation is inferred from those subtractions.

## 3. Actual reciprocal operands and all-u64 division identities

Input division uses these source bytes:

```
5631a7a  48ba9324499224499224  MOVABS RDX,2492492492492493
5631a84  48f7e2              MUL RDX             # unsigned 64x64 -> 128
5631a87  4929d7              SUB R15,RDX
5631a8a  49d1ef              SHR R15,1
5631a8d  4c01fa              ADD RDX,R15
5631a90  48c1ea02            SHR RDX,2
```

Here RAX and initially R15 hold d. Let M7=0x2492492492492493.
The exact integer identity is 7*M7=N+5. If d=7*a+b, 0<=b<=6, and
h=floor(d*M7/N), then h=a+delta with delta in {0,1}, since
delta=floor(b/7+5*d/(7*N)). The remaining source operations compute

```
floor((h + floor((d-h)/2))/4)
 = a + floor((delta + floor((b-delta)/2))/4)
 = a.
```

For both delta values and b=0..6, the final numerator inside the last floor
is in 0..3. Also h<=d and h+floor((d-h)/2)<=d, so the subtraction and
addition do not wrap. This proves floor(d/7) for every unsigned 64-bit d.

Output division is bound to:

```
5631acc  48b8cdcccccccccccccc  MOVABS RAX,cccccccccccccccd
5631ad6  48f7e2              MUL RDX
5631ad9  48c1ea03            SHR RDX,3
```

RDX initially holds r. Let M10=0xcccccccccccccccd. Exactly 10*M10=8*N+2.
The MUL high half followed by SHR 3 equals floor(r*M10/(8*N)). For
r=10*a+b, 0<=b<=9, this is

```
a + floor(b/10 + r/(40*N)) = a,
```

because the fractional sum is less than 0.9+0.025 < 1. Thus this is
floor(r/10), not the previous candidate's shift-2 divide-by-5 path.
The following CMP/CMOVA selects the unsigned minimum with floor(d/7).

## 4. Entry guard and zero quotient, before any record/refill access

The original instructions then execute:

```
5631ae4  MOV RAX,R15             # q
5631ae7  LEA R15,[RDI+RAX*4]
5631aeb  ADD R15,RAX             # stop=u(O3+5q)
5631aee  MOV RDX,[W]             # restore bit word 1
5631af2  MOV RAX,RDI             # original current O3
5631af5  CMP R15,RAX
5631af8  JE 5631ea0              # return path
```

Since q<=floor((N-1)/10), 0<=5q<N. Therefore stop==O3 iff q==0,
even if the final addition is considered modulo 2^64. There is no accidental
nonzero-q equality. Equivalently q==0 iff d<7 or some unsigned remainder
rj<10. Only under nonwrapping ordered bounds are those differences actual
available byte counts.

On the first outer evaluation, q=0 returns before any table payload/shift/
advance load, input refill, output-buffer store or BSF. It still reads state
and stack, performs arithmetic, and writes the twelve state qwords on return.
Those fields retain the initial loaded values on this first zero-q path.
After earlier batches, a later zero-q return instead writes current state.

Only after the q!=0 guard does the code perform three unsigned input-order
checks: I1>=I0, I2>=I1 and I3>=I2. Failed checks also take 0x5631ea0 before
the first inner body. It does not explicitly check L<=I0, output-region
ordering, per-record advances, or nonzero BSF operands.

## 5. Conditional per-batch cursor/write bound

The following is a conditional argument, not an assertion that an unrecovered
caller establishes its premises:

- The current output cursor Oj lies in a nonwrapping writable region ending
  at its fixed Ej; every Rj=Ej-Oj is a genuine nonnegative distance.
- The table is stable/readable at every selected 4-byte record (an 8 KiB
  envelope suffices), and each selected advance byte is 1 or 2.
- Input cursors pass the actual ordered checks, L<=I0, and a nonwrapping
  immutable readable refill region covers [L,initial_I3+8).
- Every BSF operand after its five shifts is nonzero. This condition is not
  established merely by the index width or advance condition.
- State, output regions, input region, runtime table, immutable code and the
  valid stack/return region have the required separation; pointer arithmetic
  agrees with these nonwrapping intervals. Ordinary call/return state is
  required for a return beyond the local RET.

For q>0, q<=floor(Rj/10) for every lane, hence stop=O3+5q is nonwrapping and
within lane 3's end. Each executed body advances lane 3 by between 5 and 10.
Consequently, after at most q bodies, lane 3 has reached or passed stop and
the actual unsigned `CMP [W+30],RDI; JA 0x5631b40` stops repeating. Let J be
the number of bodies in this batch; then 1<=J<=q.

For lane i there are m=5J WORD stores. Before its t-th store (t=0..m-1),
the cursor is at most initial_Oi+2*t. That store's last byte is therefore
at most initial_Oi+2*t+1 <= initial_Oi+10*J-1 < initial_Oi+10*q <= Ei.
Every two-byte store lies inside the stated output region. The final cursor
advances by 5J..10J and remains <=Ej. This proof preserves the extra physical
byte written when a record advances only one; it does not replace WORD
stores with one-byte writes.

The bounds apply inductively to every prefix of at most q bodies, so the
argument does not assume that an out-of-range write has somehow succeeded.
Each such prefix stays inside the given writable regions; at body q the
continuation comparison is false if an earlier comparison has not exited.

For each nonzero 64-bit BSF operand, z is in 0..63, so the input retreat
z>>3 is 0..7 bytes. Across J<=q refills each input cursor stays at least
its initial value-7q >= initial_I0-7q >= L. It never increases, so the
initial_I3+8 upper bound covers all eight-byte refill loads. The source
refill is `load64(updated_I)|1`, shifted by z&7; its incoming BSF must
still satisfy the explicit nonzero premise.

These are per-batch bounds. A further whole-call termination claim would
need the same premises maintained across outer recomputations and must
preserve early returns when input ordering changes. This packet makes no
whole-call termination claim.

## 6. Why the record premises cannot be silently dropped

These are mathematical counterfactual domain gaps, not target defects:

- Advance 0 defeats the progress proof. A stable record with shift 0 and
  advance 0, bit words/refill words equal to 1, and q>0 can keep every output
  cursor unchanged; BSF remains defined with z=0 and the stop stays ahead.
- Advance 3 defeats the 10-byte capacity argument. With q=1 and remaining
  region size 10, five stores at offsets 0,3,6,9,12 require bytes through
  offset 13 although the reserved amount is 10. This says the bound does
  not follow without the record condition, not that a real caller supplies
  such a table.
- Nonzero advances alone do not imply nonzero BSF operands: the shift byte
  is independently loaded and its architectural low-six-bit count can
  discard all set bits. The table producer/input invariants remain open.

Two source-bound counterfactuals explain the delivered focused controls:
(1) changing the actual divide-by-10 SHR count 3 to 2 would
give divide-by-5. With output remainder 10, sufficient input and advance 1,
q=2 permits ten overlapping WORD stores through offset 10, beyond that
10-byte region. (2) considering only lane 3's remaining space can permit
too many bodies for another lane: a slower lane 3 with advance 1 and space
20 can drive two bodies while a lane with advance 2 and space 10 needs the
actual four-way minimum to limit the batch to one body. These explain the
distinct multiplier/shift and four-output minimum without running captured code.

The delivered write-event model permits within-lane overlap for advance 1;
it does not assume individual WORD stores are disjoint or replace them with
one-byte stores. It records ordered little-endian WORD events and both byte
effects. Consumers can compose those effects at byte addresses without a
concrete CPU interpreter.

## 7. Producer binding and remaining limits

The new producer checks the actual four-byte record transfers, ordered two-byte
write/independent advance effects, four-output quotient expression, zero-q
guards and all refill equations. Its term DAG and register/memory def-use
records cover every source row. These are finite symbolic transfers, not
concrete state or loop execution. The same physical state writeback/register
context is checked for completeness; the new contribution is the record and
batch behavior beyond #1022. Arithmetic interpretation is justified by the
quantified proof above, rather than examples alone.

Caller reachability and original function identity stay unqualified. The
earlier #981 packet found no selected RELATIVE addends or raw E8/E9 byte
candidates to this entry; that absence is not a recovered caller graph.
No runtime table contents or producer were captured, and no algorithm,
private ABI/source type, Rust reconstruction, general safety, equivalence,
accepted function denominator or component gate follows.


## 8. Complete phase and memory obligations

The source partitions exactly into prologue42 rows, outer arithmetic/guards44,
stop/alignment5, inner body196, outer backedge1 and normal return36. The CFG
has nine blocks and six encoded direct branches, all local, and a sole RET.
Every decoded instruction is lifted; no unknown instruction/control transfer
is silently accepted. Original native bytes, widths and addresses must tile
all 1,269 bytes. Branch targets are independently reconstructed from signed
displacements. The three long alignment NOPs and final one-byte NOP have no
data-memory access; their memory-shaped operands are not pointer dereferences.

Before a guard exit, the prologue has exactly15 state qword reads; outer
arithmetic reads only six fixed frame qwords and writes the word1 spill.
It restores every live input/output/bit-word register before comparisons.
Thus the first q0/input-order exit has no lane/table/refill accesses and the
twelve written state qwords equal their initial loads. This is control/data
reasoning, not concrete execution of a zero-valued state. Symbolic phase
records describe transfers and conditions; they are not one runtime path trace.

Each inner body has exactly60 table-field reads, input0's frame restore,
four input qword refill reads, and the final saved-stop CMP read:66 in total.
Its only writes are input0's frame save and20 WORD output stores. Input0 is
saved before R8D becomes payload and restored at full width before refill.
The complete output-end/input-lower/state-base/saved-register protected frame
slots remain unchanged across a cycle. All output effects retain their global
round/lane order and split little-endian byte values; intra-lane overlap is
allowed. No final-memory computation assumes those individual stores disjoint.

The exit cutpoint generalizes mutable W+00 and W+30 scratch. The sixth dead
auxiliary POP at0x5631ea9 can read the initial duplicate Q or a previous stop;
it must not be attributed unconditionally to either. The next POP recovers
protected Q at W+38. The twelve state writes and saved-GPR restoration are
independent of mutable exit scratch. RFLAGS preservation is not claimed and
RET leaves RSP at entry_RSP+8. Original function/type/ABI identity is unknown.

The source helper checks the exact arithmetic expression and both reciprocal
instruction sequences. Its constant identities and14 remainder/delta cases
support the all-u64 derivation; it is not an automatic general-purpose
machine theorem prover. Independent review of the full transfer/proof and
its domain is part of qualification. No high-level examples or codec oracle
stand in for the bound argument. No captured code or CPU emulator is run.
