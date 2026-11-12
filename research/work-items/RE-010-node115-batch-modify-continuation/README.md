# Batch-modify row continuation and result association

Backlog HL115-040; bounded RE-010 research. Target Linux x86-64 node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `a8616af9432b8d8517b2af677880e117b7c28ef3`.

#4130 and `RE-010-node115-batch-modify-rows` establish row bounds and the call
to `0x5132ab0` but explicitly stop before per-row processing. This packet follows
that call through `0x5b2fbd0` into `0x5862ce0`, where every admitted row reaches
the real single-modify operation `0x555f0d0`. It closes the caller's order,
argument identity, output association, normal continuation and partial-result
ownership publication. It does not supply a pretend modifier or execute the
captured program.

## Input and result layout

`0x5132ab0` copies each 80-byte input row into separate owned storage. The copy
finishes before the `count < 10001` gate. An empty admitted input uses the
non-owning pointer value 8. Nonempty admitted counts are 1 through 10,000.
The captured context carries the same mutable owner, the same 20-byte identity
pointer and a pointer to the direction byte read from outer input `+0x18`.

`0x5b2fbd0` allocates a result vector. On the admitted domain, its byte-count
arithmetic is exactly `112 * count`: remaining input bytes are divided by 16,
then multiplied modulo 2^64 by `0x99999999999999b0`; multiplying the resulting
`5 * count` by that coefficient gives `112 * count`. Capacity is recovered by
multiplication by inverse-five `0xcccccccccccccccd`. The count is initially zero.
These are allocation/count calculations, not a claim about arbitrary malformed
pointer differences.

At `0x5862d30..0x5862da3`, iteration `i` loads row `i` in increasing physical
order. The actual call arguments to `0x555f0d0` are:

| Argument | Native source |
| --- | --- |
| RDI | Writable 112-byte stack result |
| RSI | Same captured mutable owner |
| RDX | 20-byte identity copied from the captured identity pointer |
| RCX | First 24 bytes of the current 80-byte row |
| R8 | Remaining 56 bytes of that row |
| R9B | Direction byte read from the captured pointer for this iteration |

The separate 24-byte and 56-byte lanes are not collapsed into an inferred
operation type. The identity and direction are read again each iteration; the
packet does not assume opaque modification cannot affect aliased state.

## Returned refusal does not stop the caller loop

Immediately after the call, `0x5862da8..0x5862dfe` copies all seven 16-byte
blocks of its returned value to output row `i`. It then increments the output
count by one, advances output by 112 bytes, and advances input by 80 bytes.
The only branch in this normal continuation compares input cursor with input
end (`0x5862e0e..0x5862e13`). No returned result byte or tag is tested.

Consequently, any *normally returning* refusal/error result from the modifier
is stored in its original row position and does not itself skip later rows.
This is a caller-level statement for every returned value, independent of
which exact result tags denote refusal. It does not establish the native
effects of any particular modification or atomicity of a multi-row operation.

## Normal completion and unwind are distinct

Normal completion publishes the completed result count at `0x5862e27`, then
frees the copied input allocation when its capacity is nonzero. The outer
collector returns the result descriptor.

The unwind landing pad `0x5862e5d..0x5862e99` publishes the count of results
that completed *before* the interrupted call, frees the copied input storage,
and resumes unwinding. Its caller then invokes partial result-vector cleanup
at `0x5b2fcd6`. This is not an ordinary returned refusal. The row loop contains
no owner-state restoration on that path. Whether the single-modify operation
or an outer transaction rolls back mutations remains unresolved; absence of
a restoration write in this loop cannot establish global non-atomicity.

## Validation and limits

The reproducible static verifier binds all three functions (1,183 bytes,
288 instructions) to the original digest and FDEs, checks 90 semantic facts,
and rejects 85 changed-byte/relocation controls. The complete normal
post-call continuation is inside the checked windows, including its sole
conditional next-row branch. No captured code is executed or emulated.

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-010-node115-batch-modify-continuation/verify.py --target /path/to/original/hl-node
```

Live valid input/storage, disjoint allocation ownership and the documented
call-return boundaries are premises. Modifier `0x555f0d0`, result tag names,
destructor internals, panics within cleanup, later serialization and outer
transaction commit/rollback are outside this contribution. There is no new
execution implementation and no mock callback proof. Full component and
backlog completion gates remain false.
