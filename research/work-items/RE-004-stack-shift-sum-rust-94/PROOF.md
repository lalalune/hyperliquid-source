# Full-domain value derivation

This proof concerns the exact 55 bytes in `static.json`, bound to the full node
#94 digest. GNU and Apple LLVM independently print the same 19 instruction
boundaries and bytes. Neither captured instructions nor an emulator were run.
The FDE is exactly `[0x55c6c40,0x55c6c77)`; the two-byte NOP at `0x55c6c4e` is
inside it. Nine following INT3 bytes are outside it. There are no outgoing calls,
external constant loads, writes, LSDA or relocation-covered bytes in this leaf.

Let `f`, `a`, `b` be the unsigned 32-bit words at entry RSP+8, +12, +16. The entry
RSP points at the return address. These are raw words; no boolean, enum, exponent
range, pointer layout or application meaning is inferred.

| Address | Observed operation | Consequence |
|---|---|---|
| `0x55c6c44` | `xor eax,eax` | Zero-extends to RAX = 0. |
| `0x55c6c46..0x55c6c4d` | compare stack word to 1; JE to `0x55c6c50`, otherwise RET | Exactly `f == 1` enters calculation. Other flags return 0 without reading `a` or `b`. |
| `0x55c6c50..0x55c6c5c` | EDX = `a`, EAX = `b`, ESI = 8 | Each 32-bit write zero-extends. |
| `0x55c6c5d..0x55c6c65` | compare EDX with EAX, ECX = EDX, CMOVBE EAX = EDX, SUB ECX -= EAX | Unsigned minimum selects `min(a,b)`, so ECX = `max(a-b,0)`. |
| `0x55c6c66..0x55c6c75` | EAX = 1; SHL RAX,CL; ECX = EDX; SHL RSI,CL; ADD RAX,RSI | Two 64-bit shifts with counts modulo 64, followed by addition modulo 2^64. |
| `0x55c6c76` | RET | Returns resulting RAX. |

CMOVBE uses the unsigned flags from Intel `cmp edx,eax` (AT&T `cmp %eax,%edx`). The
intervening MOV does not change flags. If `a <= b`, EAX becomes `a`; otherwise it
remains `b`. The subsequent 32-bit subtraction cannot underflow: the subtrahend
is at most `a`. Its largest possible value is `2^32-1`, representable in u32.
Consequently Rust `a.saturating_sub(b)` equals this difference for every pair,
including pairs crossing bit 31. A signed comparison or a narrowed comparison
would not preserve it.

For these 64-bit SHL instructions, only the low six count bits matter. Reading
CL first truncates to eight bits, but reducing that to six bits is identical to
reducing the whole u32 count modulo 64. Let

```text
r = a mod 64
s = b mod 64
D = max(a-b,0)           (unbounded mathematical subtraction)
d = D mod 64
```

The first result is always `2^d`, for `0 <= d <= 63`. The second is the low
64 bits of `8 * 2^r = 2^(r+3)`. It is `2^(r+3)` for `r <= 60`, and 0 for
`r in {61,62,63}`. No shift count of 64 or more reaches an unchecked Rust shift:
`wrapping_shl` masks its count exactly as required. `wrapping_add` then retains
the low 64 sum bits. Thus the safe implementation has no arithmetic panic for
any of the `2^96` input triples, even with overflow checks enabled.

If `a <= b`, `d=0`. Otherwise `d=(r-s) mod 64`. This proves that the active
value is determined by the unsigned order region and two residues; equality
has only 64 residue representatives. It justifies the complete finite semantic
partition used for representative testing. Tests exercise all 4,096 residue
pairs in both strict order regions, with both small and sign-boundary-crossing
representatives, plus equality, power boundaries and deterministic digest-derived
inputs. This reduction is a proof about the mathematical rule, not a claim that
native testing alone exhausts the full input domain or executes target behavior.

## Active zero is possible

For `r >= 61`, the second term vanishes and `2^d` cannot be zero. For `r <= 60`,
the two positive powers are each at most `2^63`. Their sum is at most `2^64`;
it is zero modulo `2^64` exactly when both are `2^63`. Hence `r=60` and `d=63`.
The latter excludes `a <= b`, where `d=0`. In the strict greater region,
`d=(r-s) mod64=63` with `r=60` is equivalent to `s=61`. Therefore

```text
flag == 1 and result == 0
    iff flag == 1 and a > b and a mod64 == 60 and b mod64 == 61.
```

For example `(1,124,61)` and `(1,2147483708,61)` both return 0. Saturating the
final addition would instead return `u64::MAX`. Zero is a raw value shared by
all inactive triples and these active triples, not a recovered error sentinel.

## Caller and original ABI limits

The complete caller FDE is `[0x555b930,0x555bbf8)` (712 bytes, 191 instructions).
Its first relevant origin is `mov rsi,r14` at `0x555b93a`; the full disassembly
shows no intervening definition of R14 before the call. At `0x555ba4b`, MOVDQU
loads the first 16 bytes from R14 to XMM0. The caller reserves 32 stack bytes at
`0x555ba55`, stores XMM0 at the resulting RSP at `0x555ba63`, and copies another
8 bytes from R14+16 to RSP+16. It calls the selected leaf at `0x555ba70`.

CALL pushes an eight-byte return address. Thus leaf RSP+8/+12/+16 correspond
to pre-call RSP+0/+4/+8, which contain the first three u32 words of that copy.
The extra copied bytes are not consumed by this leaf. The stores at
`0x555ba59` and `0x555ba5e` are at RSP+64 and +60; they do not overlap these
arguments. The result is moved from RAX to R12 at `0x555ba7d`. The adjacent
call at `0x555ba8d` targets `0x55c6c80`, a different FDE, and is not part of
this component. No whole-caller behavior or source type has been recovered.

The sole `.text` E8 byte-pattern candidate targeting the leaf is `0x555ba70`,
and both complete caller decoders establish it as an instruction boundary.
That scan is not an indirect-call or data-pointer census. All ELF RELA records
are checked for addends naming the leaf and for conservatively eight-byte
relocation overlaps with the leaf/padding and caller. No such records occur.
Caller data dependencies elsewhere in its body remain outside this value scope.

The normal-return relation assumes the flag word is readable, the other two
words are readable when the flag is 1, and RET has its ordinary valid behavior.
The safe by-value API does not expose inaccessible stack memory, read order,
return-address faults, register clobbers, original ABI packaging or unwinding.
The original library and symbol remain unknown; addresses carry the identity.
