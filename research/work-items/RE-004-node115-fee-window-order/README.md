# RE-004: node115 fee-associated adjacent binary64 ordering scan

- Component: fees. Bounded static research, not a whole fee-table validator.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: what does the adjacent-value scan consider a match, including
  equality/unordered values, and how does its observed size-two caller use it?
- Included: full FDE exports `0x36e1b10..0x36e1b81` (113 bytes, 33 instructions)
  and caller `0x36a1c20..0x36a31ff` (5,599 bytes, 1,150 instructions), unwind
  records, calls, source Location and relocations.
- Excluded: complete table validation, input provenance or NaN admission,
  original Rust signatures, floating exception environment, original execution
  and implementation equivalence.

Addresses are ELF virtual addresses. Original bytes, file offsets, hashes,
native disassembly and raw FDE/CIE records are retained. Complete caller export
does not imply that the caller's entire semantics have been analyzed.

## Scan and state observations

The argument points at three raw words: a pointer at +0, remaining count at +8,
and requested window width at +16. For width at least 2:

1. If remaining count is below width, return AL=0.
2. Otherwise decrement the count, store it and the next-element pointer back
   to the argument, then load the next binary64 and compare it with its
   previous element using UCOMISD at `0x36e1b46`.
3. JBE at `0x36e1b4f` continues when next <= previous **or the comparison is
   unordered**. The LEA between compare and branch does not alter flags.
4. Ordered next > previous returns AL=1, set before UCOMISD by the admitted
   window-count check. Exhausting possible windows returns false.

The caller explicitly supplies width **2** at `0x36a2826`; consequently it
scans exactly adjacent pairs. For valid readable input this establishes an
`any(next > previous)` predicate, not strict decreasing order and not a total
ordering. Equal finite values and both signed zeros do not trigger true;
positive/negative infinities use their ordered relation. A NaN comparison
continues through the unordered flag path **if the floating environment lets
UCOMISD return**. This packet does not establish MXCSR exception masks,
signaling-NaN handling, or that such values can reach the call.

For raw widths 0 or 1, zero remaining count returns false. Nonzero count first
advances/decrements the raw state then calls `0x64df620 -> 0x1680cbf`, with
the authenticated Location at `0x6468b98`, `l1/src/fees/fees.rs:259:57`.
That invalid-width path does not return within the exported body. It is not a
supported caller case: the measured caller uses constant 2. Generalizing the
size-two predicate to arbitrary widths or treating invalid state as a safe
public API would be unsupported.

At `0x36a2832..0x36a283a` the caller passes a stack state populated from its
earlier values, calls the scan, and tests AL. A true result branches at
`0x36a2841` to `0x36a2ad6`; false continues at `0x36a2847`. This shows an
ordering-failure branch for this local check. Other branches in the retained
caller impose their own conditions; this finding is **not** evidence that a
whole fee configuration with NaNs/equalities is accepted. Original fee roles,
table element names and complete failure diagnostics remain unresolved.

## Reproduce and controls

From the repository root on Linux, Python 3.12 and GNU binutils 2.42:

```sh
python3 research/work-items/RE-004-node115-fee-window-order/collect.py \
  --output work/node115-fee-window-order --check
python3 -m unittest discover -s tests -p test_node115_fee_window_order_static.py -v
make doctor verify test reproduce
make catalogue-check
git diff --check
```

The collector authenticates the original before a private 0400 static-tools
snapshot, agrees on unwind/relocation data with independent readelf output,
and requires complete contiguous objdump byte coverage. Claimed anchors must
be real decoded instruction starts. No CPU/instruction evaluator or emulator
is used, and captured code is never executed.

Four controls reproduce every retained export, verify the original anchors,
reject separate private byte corruptions of each claimed anchor (including
the UCOMISD/JBE sequence and caller rejection), and reject the wrong complete
image before native tools/output. These check the evidence machinery; they do
not establish runtime floating-point behavior or reconstruct Rust.

## Results and limits

The exports total **5,712 bytes / 1,183 instructions**. Those sizes are static
evidence denominators only; compared implementation bytes are zero. There is
no source build, binary match, normalization mask or component gate claim.
New research/tooling is independently authored under root MIT; no unlicensed
inferred implementation was read or copied.

Next: trace the originating table and all caller guards to establish whether
nonfinite entries are excluded, then qualify a Rust predicate with an explicit
floating environment and caller-owned contracts.

Native text exports trim trailing whitespace only; instruction bytes, operands and addresses are unchanged.
