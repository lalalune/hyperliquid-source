# RE-004 — Node #115 decimal formatter scale and result layout

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the digit extraction in #7458 into its formatter's local layout stage.

The helper takes the original scale byte from bits 16–23 of the input flags. If that scale exceeds the extracted digit count, it extends the reverse-order dword digit scratch area with ASCII zero and uses the scale as the new digit count. When that adjusted count equals the scale and the requested output has digits, it emits the leading `0.`. In the interior-point path the reverse digit loop emits a literal dot when the reverse index reaches scale minus one, then emits the digit at that position. The loop also has a distinct ASCII zero store after scratch digits are exhausted.

Without an explicit-precision flag the requested scale is the original scale. With the flag and a requested precision of 29 or more, the local stage limits precision to 28 and saves the excess count for the outer formatting path in #7451. The final handoff stores a length dword at result +0, a 32-byte inline region at +4 and the excess-present flag and associated word at +0x28 and +0x30. The inline region is meaningful only through its length.

These are selected local formatting stages. This packet leaves overflow branches, full formatting-context behavior and terminal sink output outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-004-node115-decimal-scale-layout/verify.py` to check the static windows and branch targets.
