# RE-004: node115 fee-associated checked active-field scaling

- Component: fees. Bounded static research; no Rust reconstruction claim.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: which raw active fields are multiplied by 100, what selects their
  paths, and where does one caller pass the resulting representation?
- Included: complete FDE exports `0x46a6860..0x46a69cf` (367 bytes,
  100 instructions) and `0x44896f0..0x448a362` (3,186 bytes, 680 instructions),
  original bytes, calls, source Location and relocations.
- Excluded: original type names, fee units, inactive fields, owning ABI, helper
  implementations, complete caller semantics, target execution and Rust builds.

Addresses are ELF VAs, with file offsets/body hashes and raw unwind records
in `records.json`. Full exports preserve surrounding branches; their sizes
are not a measure of reconstructed code.

## Observed projection

RSI is the input and RDI the output address. Unsigned MUL followed by JO checks
that each active multiplication fits u64; it does not round, saturate or clamp.
For scale 100, the admitted value is `x <= floor((2^64-1)/100)`
(`184467440737095516`). The guard rejects the next integer. The exact instruction
ordering establishes these paths:

| Input word | Selection | Normal output word |
| --- | --- | --- |
| +0x60 | Always, first | +0x60 = input * 100 |
| +0x68 | Always, second | +0x68 = input * 100 |
| +0x08 | Only raw word at +0 equals 1 | +0x08 = input * 100; output+0 is 1 |
| +0x40 | Only raw word at +0x28 differs from `0x8000000000000000` | +0x40 = input * 100 |
| +0x70 | Always, after optional branches | +0x70 = input * 100 |

For raw outer word other than 1, output+0 is zero. That condition is an exact
equality test, not generic nonzero truthiness; it does not establish that other
words are valid original enum states. In the selected outer path a 20-byte
payload at input+0x10 is copied via stack to output+0x10.

The inner bypass is implemented by NEG on the raw input+0x28 word and a JO/JNO
pair. Two's-complement NEG overflows exactly at the bit pattern
`0x8000000000000000`. This is a representation sentinel observation; calling
that field a signed fee or a valid negative amount would be unsupported. On
the non-bypass path the code copies a 20-byte payload from +0x48 and the raw
word at +0x38; the words at +0x28/+0x30 are preserved. On the bypass path,
inactive output registers/stack bytes do **not** establish meaningful values.
No claim is made about those inactive fields or padding.

The normal-return stores occur only after all active multiplications succeed.
The three failure funnels at `0x46a696c`, `0x46a697b` and `0x46a698a` reference
the same authenticated `l1/src/fees/compute.rs:45:42` Location at `0x6493610`,
and call `0x64df830 -> 0x1680c10` before UD2. The precise diagnostic helper and
unwinding behavior remain unresolved. The cleanup tail contains a conditional
deallocation through `0x64df4a0 -> 0x635de30` and `_Unwind_Resume@plt`; no
whole ownership model is inferred from that tail.

The caller supplies output stack+0x120 and input stack+0x90 at `0x4489d47`,
calls this body at `0x4489d52`, then passes the output address as RCX to
`0x3c1ae50` at `0x4489d83`. Its later inspection of output+0x28 compares against
the same minimum-word sentinel before deallocation. These links support a
representation conversion interpretation, but do not identify source struct,
fee-rate unit, decimal denominator or the callee's business policy. This is
one confirmed call path, not a complete call census.

## Reproduce and controls

From the repository root on Linux, Python 3.12 and GNU binutils 2.42:

```sh
python3 research/work-items/RE-004-node115-fee-scaling/collect.py \
  --output work/node115-fee-scaling --check
python3 -m unittest discover -s tests -p test_node115_fee_scaling_static.py -v
make doctor verify test reproduce
make catalogue-check
git diff --check
```

The collector authenticates the whole original and exports a private 0400
snapshot only to static GNU tools. Independent Python ELF/FDE/relocation walks
must agree with readelf, and objdump must cover every exported byte. All
arithmetic/path/caller anchors must start at decoded instruction boundaries.
Records include complete body hashes, raw FDE/CIE records, call/import bindings
and the source Location's original pointer/length/line/column bytes.

Four controls verify regenerated exports, original anchors, isolated corruption
of each anchor, and a wrong whole-image identity that must fail before native
tools/output. They do not execute or emulate the captured code. No source
function or source-compatible ABI has been implemented; there is no compiled
comparison or normalization mask to report.

## Results and limitations

Exports cover **3,553 bytes / 780 instructions**, of which the selected leaf
is 367 bytes / 100 instructions. These are export denominators, not recovered
implementation coverage. Implementation bytes and accepted gates remain zero.
The packet is independently authored under root MIT without reading or copying
unlicensed inferred source.

Next: recover the original active-field contracts and `0x3c1ae50` input handling
to assign units and validate an independently authored Rust conversion without
exposing inactive bytes as initialized values.
