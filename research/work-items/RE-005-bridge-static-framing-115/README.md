# RE-005: bridge input tags and conditional static-word framing

The bridge request's 52-byte input is not handed directly to its digest helper.
It is first converted into two tagged records, normalized, and passed through a
word-based serializer. This packet resolves the tags, selected normalization,
head/tail accounting, and relevant word views. It does not claim to have executed
the complete serializer, allocator, copy, digest or bridge operation.

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `05bc2de303c05525b71e7e257426e741bc66a390`. Task RE-005, bridge allocation.
Merged #2271 maps the containing request and explicitly leaves `0x4302cd0` and
its serialized content opaque. That original packet remains credited context.
The generic codec bodies below are dependencies for this concrete private
question; they are not separate first-party recovery or contribution claims.

## What the private builder actually constructs

The new private FDE is `0x4302cd0..0x4302e41`: 369 bytes / 89 instructions.
The full caller and selected codec contexts add 4,062 bytes / 1,046 instructions.
The complete retained export is therefore 4,431 bytes / 1,135 instructions.
This is an evidence denominator, not a semantic-completion percentage.

The builder retains incoming RSI as a 52-byte input view. It calls the same
allocation-like slot with size-like RDI values 80, then 32. On the non-null
routes it prepares two records at 40-byte stride:

- First record: raw byte tag 0, followed by the first 20 input bytes.
- Second record: raw byte tag 1 and a three-word `(32, pointer, 32)` descriptor.
  The pointer receives input bytes `+20..+52`, half-open, in two 16-byte copies.

These are local raw layouts. Original enum names, a public address type, and
source ownership are not recovered. Some record padding is copied from otherwise
uninitialized stack bytes; it is not assigned fabricated values. The selected
codec paths read the active fields, not a made-up fully initialized structure.

The two input parts are loaded after different allocation calls. Stable input,
disjoint writable allocations, ordinary helper returns and ABI preservation are
premises for treating them as one snapshot. No atomic read or allocator purity
is proved. Allocation failure, cleanup/drop and unwind paths remain context.

At `0x4302d85`, the actual slot `0x64e0140` resolves to `0x169e350` and receives
count 2. The surrounding request/source Location binds this helper to
`l1/src/bridge_request.rs:83:78`; it does not recover an original function name.

## Normalization and length units

The 40-byte-to-32-byte normalization loop calls `0x169dcc0`. Its signed-relative
10-entry table at `0x47b72c` dispatches raw tag 0 to `0x169dce3` and raw tag 1 to
`0x169ddb9`. Both become normalized class 0 with count 1 for the selected input:

- Tag 0 writes the combined class/count word `0x0000000100000000` and retains
  the original record pointer.
- Tag 1 computes `(length + 31) >> 5`, checks the addition bound, stores that
  u32 count beside class 0, and retains its original record pointer. Length 32
  therefore gives count 1; it does not add a dynamic-length word.

For class 0 / count 1, head helper `0x169e650` returns 32 and tail helper
`0x169e6d0` returns 0. The latter's actual jump-table target is its zero-tail
return. Thus the selected pair has head accounting 64 and tail accounting 0.
These quantities must not be confused with the intermediate allocation request:
`0x169e350` shifts the summed value left by 5 before its allocation-like call,
so this particular path passes RDI = 2,048. The word buffer's capacity-like value
is 64. This is observed request arithmetic, not measured heap consumption or an
assertion that the original allocator/codec is defective.

Changing only the private second tag byte from 1 to 2 would select normalized
class 2 with count 2 at length 32. The same accounting helpers then give head
32 and tail 64 for that second record: total pair accounting 128 instead of 64.
This is a decoded static counterfactual, not an executed modified bridge trace
or proof that arbitrary raw tags are admitted source variants.

## Selected word views and remaining boundaries

The class-0 head writer tail-jumps to `0x169df80` with the retained original
record. Its raw tag-0 branch explicitly prepares twelve zero bytes followed by
20 input bytes, then appends that 32-byte word and increments the word length.
Its raw tag-1 branch zeroes a 32-byte local word and requests a copy of up to
32 payload bytes. At length 32 the copied word has exactly the selected payload;
there is no extra length word on this selected branch. The second pass's class-0
jump-table target skips a tail append.

Consequently, under the stated ordinary-copy/append/flatten premises, the two
selected word views are `zero12 || input20` and `input32`, in that order.
The static plan's examples illustrate those views only. The copy slot, growth,
final flatten helper, returned buffer ownership and digest results are still
unclosed; no end-to-end native encoding vector or complete ABI implementation
is claimed. Other token/normalized classes are context, not a recovered generic
codec. An ABI-like interpretation does not establish a dependency name/version.

## Evidence and reproduction

```sh
python3 research/work-items/RE-005-bridge-static-framing-115/collect.py --output work/bridge-framing-replay --check
python3 research/work-items/RE-005-bridge-static-framing-115/analysis.py
python3 -m unittest discover -s tests -p test_bridge_static_framing115.py -v
```

The collector authenticates the whole target before tools/output. Complete
Python/readelf FDE/CIE/RELA and GNU/Capstone instruction partitions agree.
Four relative dispatch tables are retained and checked against their actual
owning instruction starts. Selected real-byte structural corruptions run below
the whole-image identity gate. They authenticate evidence; they are not changed
native output vectors or a Rust differential oracle.

Initial collection passed its exports in 115.501 seconds, but a manually entered
context subtotal was six bytes too small. The original record/log are retained.
The published collector derives both role subtotals from actual FDE lengths;
its fresh collection is recorded separately. No earlier metadata error is
presented as a correct subtotal. No captured process, interpreter, live service,
network/chain action, signing, keys or wallet operation is used here.

New analysis is MIT; the project fee-scaling/limiter collector scaffolding is
credited. Original bridge evidence, tools, captures, imports and pins remain
unchanged. All component gates and registered compiled windows stay false.
No original public ABI, source types, units, full serializer/hash/bridge, source-
built node or binary equivalence is claimed. Next close the selected copy and
flatten contracts before comparing a complete serialized buffer.

Final collection passed in 107.252 seconds. The 369-byte / 89-instruction
private builder and 4,062-byte / 1,046-instruction context agree with both
native decoders and the unwind/relocation readers. Twenty-six actual-byte
structural controls passed in 1.319 seconds. Seven focused checks passed in
6.332 seconds; the final test replaces a redundant example-consistency check
with the actual codec relocation and source-Location check. The earlier seven-
check log (6.991 seconds) remains separate. Neither run executed the codec.

Catalogue generation/check alone uses the already-submitted #2655 snapshot-read
fix for the measured 39.47 GB repeated-read blocker. The baseline helper is
restored before actual reproduce/final audit and remains unchanged in commits.
This is not an unmodified-head local catalogue claim. The full repository test
suite/new-head hosted CI remain pending. Integration results follow below.

Integration passed in 412.789 seconds: all 15 regenerated files were byte-exact, 12 packet-integrity tests passed, and doctor, verify, catalogue/check and actual reproduce passed. Catalogue alone used the disclosed temporary overlay; the baseline helper was restored before reproduce. Full new-head hosted CI remains pending.

Final audit passed in 2.626 seconds: all 38 manifest entries at audit time, the 15 regenerated files, all original evidence and baseline tools, and three catalogue scope tests. Archiving this receipt adds one manifest entry.
