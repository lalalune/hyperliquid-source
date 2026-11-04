# RE-001: node #115 fee-schedule finiteness gate `0x3d3b6c0`

- Component: `fees`. This is the second follow-up to `RE-001-node115-fee-schedule-gate` (#2153) and `RE-001-node115-fee-schedule-sources` (#2162).
- Target #115: 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Question: what does `0x3d3b6c0` (called at `0x36a2651`, before the ordering chain) compute? Can it fail the gate, and does it mutate the slices it is handed?
- Claim status: byte-derived observations plus conditional normal-path relations. No Rust reconstruction, oracle or progress gate.

## Result

`0x3d3b6c0` (complete FDE `0x3d3b6c0..0x3d3bb55`, 1,173 bytes) is a chained
**"any element is not finite"** scan. It returns AL=1 at the first element
whose bit pattern satisfies `(bits & 0x7fffffffffffffff) > 0x7fefffffffffffff`
(signed), and AL=0 once every part is exhausted. That is exactly NaN, +inf or
−inf. The mask and limit are read from the movabs immediates of every part. The
caller fails on a nonzero AL (`test al,al; jne 0x36a2ad6`), which is the shared
EAX=0 failure entry from #2153.

**Coverage**, decoded from the caller's construction of the 0xe8-byte state at
`[rsp+0x140]` (callee offset = rsp displacement − 0x140):

| Callee part | State | Caller fields | Iterates |
| --- | ---: | --- | --- |
| front range `+0x80` | 1 | `[rsp+0x1c0]=0` | empty |
| array `+0x50..+0x58` over `+0x60..` | 1 | idx 0, end 4; `&[rsp+0x88]`, `&[rsp+0xa0]`, `&[rsp+0xb8]`, `&[rsp+0xd0]` | **slices 1–4**, every element (`[vec+8]` × `[vec+0x10]`) |
| back range `+0x90` | 1 | `[rsp+0x1d0]=0` | empty |
| `+0xa0..+0xa8` | 2 | `[rsp+0x20]`, `+[rsp+0x28]*8` | **slice 5** |
| `+0xb0..+0xb8` | 3 | `[rsp+0x38]`, `+[rsp+0x40]*8` | **slice 6** |
| `+0xc0..+0xc8` | 4 | `[rsp+0x50]`, `+[rsp+0x58]*8` | **slice 9** |
| `+0xd0..+0xd8` | 5 | `r14`, `+r15*8` | **slice 8** |
| `+0xe0..+0xe8` | 6 | `rsp+0x230..rsp+0x240` | **`input+0x88`, `input+0x90`** (copied from `[rsp+0x100]` at `0x36a2462`) |
| tag `+0x0`, `+0x8..+0x40` | 7 | `r13`, `r9..r12`, `rbx` | values of the `input+0x48` structure |

**Not covered:** slice 7 (the u64 cutoffs) and the stake pairs
(`input+0x38/+0x40`). The stake check in #2153 already rejects NaN, and an
infinite stake value fails either its strict increase or its final cap.

### Consequence for #2153 and #2162

#2153 documents several orderings that let a NaN pair through: slices 1–6, the
strict f64 slice 8, the `fees.rs:259` helper on slice 9, and the `[0,1]` ranges.
Those local relations are correct. On this validator's normal path, however,
**every one of those values has already passed this finiteness gate**, so NaN
and ±inf there are rejected before the ordering chain runs. The tests show both
halves: the ordering model alone accepts the documented NaN cases, and the
gate plus the ordering model rejects them.

The callee's only stores go through RBX, its own state, or `r14 = rbx+8`
(`0x3d3ba2f`). Its only call is `0x37c7260`, the map iterator, and it makes no
indirect calls (`callee-effects.json`, from native decoding). So the callee does
not write the slices. This resolves #2162's main caveat **conditionally**:
`0x37c7260` receives the state pointer and is opaque.

## The `input+0x48` structure (state 7)

The caller tests `neg [input+0x48]` for signed overflow (`0x36a247a`, `jno`).
- **Value is `i64::MIN`:** the tag in `r13` is 0 or 1, from whether
  `[input+0x50]` is nonzero, and the callee advances an opaque iterator
  (`call 0x37c7260`) whose returned `rdx` points at the checked f64.
- **Otherwise:** the caller splits a ring buffer into two contiguous ranges of
  32-byte items, using pointer `[input+0x50]`, head `[input+0x58]`, length
  `[input+0x60]` and capacity `[input+0x48]` (`cmovae`/`sub` at
  `0x36a24bd..0x36a2505`), and sets tag 2. The callee checks `item+0x18` of
  each item, advancing by `lea rdi,[rsi+0x20]`.
- **Tag 3:** no items.

Reading this as an enum with a niche (`VecDeque<_>` vs a map) is an
**inference**. The item type and the iterator's internals are not recovered.

## Reproduce and validation

Python 3.13.18, Linux x86_64, GNU binutils 2.42. From repository root:

```sh
python3 -B tools/fee_schedule_finite_static.py --output work/fee-schedule-finite115
python3 -B -m unittest discover -s tests -p test_fee_schedule_finite_static.py -v
make doctor verify test catalogue-check
(cd research/work-items/RE-001-node115-fee-schedule-finite && sha256sum -c MANIFEST.sha256)
```

`certificate()` decodes the following from bytes:
- the dispatch compares;
- every part's begin and end fields;
- the mask and limit immediates and the flag condition;
- the state successors;
- the array part's index, end and table fields and vector pointer/length offsets;
- the map part's stride, value field and iterator call;
- the caller's state stores, header LEAs, slice pointer/length loads, the range copy and the failure branch.

`_analyze()` additionally requires the non-finite predicate on every part and an
initial state of 1, then pins the callee FDE and body hash. It also re-runs the
#2153 obligations.

Five focused tests cover:
- regeneration;
- the predicate on ±0, subnormal, ±MAX, ±inf and ±NaN;
- the decoded coverage;
- six synthetic schedules with NaN or ±inf in covered fields, which are rejected,
  alongside the ordering-only model that accepts one of them;
- three counterfactuals: a limit of `0x7ff0000000000000` lets inf pass, an array
  end of 3 drops slice 4, and a moved header LEA changes the coverage;
- 11 corruption controls below the identity gate, each rejected.

No captured code was executed. Imports, pins and gates are unchanged.

## Limits and next question

Not claimed:
- the internals of `0x37c7260`;
- the item and value types of `input+0x48`;
- the success path after the ordering chain;
- other callers of `0x3d3b6c0`;
- panic and unwind behaviour.

Next question: the post-gate path (`0x36a2a8b` onward, including `0x36a58d0`),
which decides when the validator returns true.
