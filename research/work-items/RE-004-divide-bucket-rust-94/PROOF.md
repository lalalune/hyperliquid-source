# Normal-return bucket and the explicit zero-divisor refusal

Let `n` and `d` be raw RDI and RSI, each in `[0,2^64-1]`. The byte-bound leaf
starts with `xor edx,edx; mov rax,rdi; div rsi`. A 32-bit register write clears
the upper half, so the unsigned 128-bit dividend RDX:RAX is exactly n, with
zero high word. When `d > 0`, the quotient `q=floor(n/d)` lies in
`[0,2^64-1]`; unsigned quotient overflow is impossible. When `d=0`, DIV raises
divide error and the leaf has no normal return, including when n=0.

The proof assumes intact code and a valid normal return stack. Exception
delivery, flags, physical register clobbers and original ABI are not projected
into the new API. Its `None` is an explicitly new refusal for d=0, not a claim
about the target's response after a trap or any handler.

## Five independent tests and a different final step

For d>0, RAX retains q during all five conditional tests. Before each shift,
q is copied afresh into RCX, RDX or RDI. Therefore each `shr k` tests the
original q rather than the preceding shifted result. Logical right shift by
k yields zero exactly when `q < 2^k`.

| First satisfied test | Remaining q interval | Return |
| --- | --- | --- |
| `q >> 1 == 0` | 0..1 | 0 |
| `q >> 2 == 0` | 2..3 | 1 |
| `q >> 3 == 0` | 4..7 | 2 |
| `q >> 4 == 0` | 8..15 | 3 |
| `q >> 5 == 0` | 16..31 | 4 |

The remaining path has q>=32. It shifts RAX by six, takes the resulting
nonzero flag with `setne al`, zero-extends that byte into EAX and adds five.
Thus q=32..63 returns 5 and every q>=64 returns 6. Zero extension makes the
entire RAX word equal to the result. The other return arms also write EAX and
therefore return zero-extended values 0..4. There is no sixth conditional
branch, no table and no bit-scan instruction in the capture.

All five branches land on the documented return blocks. The three internal
NOP sequences occupy 17 bytes between return blocks; no valid entry path
falls through a return into them. Their bytes remain included in the complete
114-byte FDE binding. A memory-looking NOP operand is not a data load. The
leaf has no call, external data dependency or external jump.

## Independent threshold oracle

For positive d and integer k:

```text
floor(n/d) >= 2^k  iff  n >= 2^k * d
```

Counting the true comparisons for k=1..6 gives zero when q<2, the binary
integer logarithm when 2<=q<64, and six when q>=64. The oracle performs only
these unbounded-integer multiplications/comparisons. It does not divide, take
a logarithm/bit length, use the Rust leading-zero method or evaluate captured
instructions. Products as large as `64*(2^64-1)` are preserved rather than
wrapped; thresholds beyond u64 simply cannot be met by a u64 dividend.

The d=0 rows in the validation corpus assert the new API's refusal only. They
are counted separately and do not invent native target outputs or execute a
hardware divide error.

## Rust expression and range safety

The safe function first returns None for d=0. Its unsigned `n/d` cannot panic
or overflow on the remaining domain. q<2 returns Some(0) before the logarithm
calculation. For q>=2, `q.leading_zeros()` is between 0 and 62, so
`63-leading_zeros(q)` is well-defined in 1..63. Capping that result at 6 gives
exactly the table above; converting 0..6 to u8 loses no bits. There are no
variable shifts or overflowing arithmetic in the library.

This partitions every u64 pair into the no-normal-return target domain d=0
and the normal-value domain d>0. The proof relates the captured returned word
to the Rust expression; it does not prove compiler correctness or whole-node
equivalence. Finite native cases exercise the compiled new source separately.

## Observed caller

The complete caller FDE is `[0x4f9cf20,0x4f9d393)`. Its instruction at
`0x4f9d21d` writes immediate `0x80000` to ESI, zero-extending it to RSI;
`0x4f9d222` copies R14 into RDI. The five following instructions store R9D,
R8, ECX, XMM1 and XMM0 to RBP-relative stack locations. None rewrites RSI or
RDI. The direct relative call at `0x4f9d240` then targets the selected leaf.
Consequently this observed call uses divisor 524288 and admits every R14 word
as a nonzero-divisor call. No meaning or reachable value set for R14 is inferred.

The one direct-e8 candidate was confirmed as a caller instruction start.
This is not a complete indirect/tail-call census or proof of the caller's
complete control flow, side effects or error handling.
