# RE-004: node115 PDI-associated bounded range generation

- Component: assets. Bounded static research, not an implementation claim.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: what range and checked arithmetic does the PDI-associated allocation
  body establish, and how does one observed caller consume its output?
- Included: complete native exports of `0x22b3160..0x22b3298` (312 bytes,
  93 instructions) and caller `0x2913750..0x2914169` (2,585 bytes,
  500 instructions), their unwind records, calls, relocations and Location.
- Excluded: original Rust types, asset-unit assignments, allocator implementation,
  complete caller behavior, original execution and reconstructed Rust.

All addresses below are ELF virtual addresses. `records.json` gives exact
file offsets, full body hashes and raw FDE/CIE bytes. An unwind extent is an
export boundary, not a proof that every semantic function is recovered.

## Observations and arithmetic relation

The input at RSI supplies raw words `O=[RSI]`, `a=[RSI+8]`, `b=[RSI+16]`.
At `0x22b3175`, unsigned subtraction plus CMOVB forms `n=max(b-a,0)`.
The allocation request is `8*n`. The separate shift-by-61 and unsigned compare
against `0x7ffffffffffffff8` reject a wrapped or overlarge allocation size.
Together they admit exactly `n <= 2^60-1`, before invoking the allocation
helper via `0x64df480 -> 0x6355830`. An empty range uses raw pointer word 8,
zero capacity/count and no read through O. The allocation-failure path calls
`0x64df498 -> 0x141e264`; its internal behavior is not reconstructed here.

For a nonempty admitted allocation, the loop at `0x22b31f0` reloads `[O+0x50]`
on each iteration, multiplies that unsigned word by **10,000**, and branches
on MUL overflow. The subsequent LEA/ADD/CMP/JB guard checks the formed word
before storing it at `[result_pointer+8*i]`:

```
word_i = 10000 * word_at_O_plus_0x50 + a + i
0 <= i < n
```

This equation assumes the relevant object word is stable during the call.
No synchronization or concurrent-mutation guarantee is inferred. MUL requires
`word_at_O_plus_0x50 <= floor((2^64-1)/10000)`. The addition guard is also exact
under the range invariant: for `b>a`, `a+i < b <= 2^64-1`. Thus `a+i` cannot
wrap; adding that value to the admitted product has at most one carry, and
the final result is below the product exactly when that carry occurred. This
explains the compare against the product rather than an assumed saturating sum.
On a later iteration the old values can already be in allocated storage before
an arithmetic failure; no transactional output guarantee is claimed.

Both failure sites bind `l1/src/asset/pdi.rs:32:14` through actual Location
slot `0x64443f0`, its RELATIVE path relocation, length/line/column, and decoded
LEA instructions at `0x22b3247` and `0x22b3256`. Multiplication calls
`0x64df870 -> 0x1681dc0`; addition calls `0x64df520 -> 0x1681da0`.
These are observed call bindings, not recovered panic implementations.

Normal output stores n at output+0, the allocated pointer at +8, and generated
count at +16. The vector-like interpretation is an inference, not an original
Rust layout claim. The caller at `0x2913ed4..0x2913ee4` constructs an input with
start 0, end taken from its object+0x10 and object pointer at its stack+0x1e8.
It passes stack+0x80 as output, reads its count/pointer, and loops over 8-byte
words, passing each to `0x2bee760` at `0x2913f35`. That callee remains opaque.
This is one confirmed caller; no exhaustive call census is claimed.

## Reproduce and controls

From the repository root on Linux with Python 3.12 and GNU binutils 2.42:

```sh
python3 research/work-items/RE-004-node115-pdi-range/collect.py \
  --output work/node115-pdi-range --check
python3 -m unittest discover -s tests -p test_node115_pdi_range_static.py -v
make doctor verify test reproduce
make catalogue-check
git diff --check
```

The collector authenticates the complete target before making a private 0400
copy for GNU objdump/readelf; it never runs or emulates captured instructions.
Python ELF/FDE/relocation parsing and GNU readelf must agree. GNU objdump must
cover every exported byte, with each claimed anchor at a decoded instruction
boundary. Retained native call bindings include imports outside the bounded
arithmetic claim; they do not establish dependency closure.

Four tests regenerate the retained exports byte-for-byte, check original
anchors, corrupt every claimed anchor separately in private bytearrays and
reject each mutation, and reject a wrong whole-image digest before invoking
native tools or creating output. These validate the evidence collector, not
runtime behavior or newly authored arithmetic equivalence.

## Results and remaining work

The two complete exports contain **2,897 bytes / 593 instructions**. This is an
evidence-export denominator only: reconstructed/compared implementation bytes
are **0**, and no raw or normalized implementation match is asserted. No
component gate is requested. New analysis/code is independently authored under
the root MIT license; no inferred reference implementation was read or copied.

Next: establish what the object word at +0x50 means, its source of truth and
stability, and the input/output contracts of `0x2bee760` before assigning asset
semantics or writing a source-compatible quantity component.
