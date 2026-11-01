# RE-004: reconstruct binary64 round across target RC modes

- Component: foundation; bounded RE-004 arithmetic reconstruction.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  Its unlicensed inferred implementation was not read or copied.
- Included: complete 113-byte/24-instruction body, unique FDE/CIE records,
  two 128-bit constants, relocation slot, returned-bit proof for four RC
  modes, independently authored Rust and frozen native checks.
- Excluded: unmasked exceptions, flags, upper XMM lanes, original ABI/source
  identity, callers' MXCSR setup, target compiled bytes and node integration.

Earlier `RE-006-mid-market-order-94` and TWAP work uses `0x565f410` as a
rounding edge. This packet adds independent Rust and explicitly qualifies
the addition's rounding-mode dependency. No prior instruction evaluator is
executed or used to generate expectations. No ceil/floor component is a
build dependency, and no previous packet is edited.

The original constants form `copysign(0.5-2^-54,x)`, added before a bitwise
truncation. A plain unconditional integer-rounding API would miss directed
mode results. For positive 0.5, RC=nearest/toward-positive returns 1, while
toward-negative/toward-zero returns 0. Positive 2^52 increases to 2^52+1 under
toward-positive addition even though the input is integral. The largest
finite input similarly reaches infinity. Signaling NaNs are quieted.
`PROOF.md` derives all cases and explains why DAZ/FTZ cannot change low result
bits under the masked-exception premise.

## Reproduce

From repository root, with authenticated artifacts and submodules:

```sh
PATH="/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH" \
  LLVM_OBJDUMP=/usr/bin/objdump make doctor verify catalogue-check reproduce
python3 -B research/work-items/RE-004-round-modes-rust-94/verify_static.py
task_rustc=$(rustup which --toolchain 1.94.1 rustc)
python3 -O -B research/work-items/RE-004-round-modes-rust-94/verify_rust.py \
  --rustc "$task_rustc" --out work/round-modes-review
```

The native validator pins the actual macOS arm64 rustc 1.94.1 executable hash
and commit, records `/usr/bin/cc` identity, and uses explicit target/edition/
optimization/overflow/linker/path-remap flags. The standard libraries belong
to that installed toolchain; this does not recover the target's build recipe.
`commands.json` retains exact commands with checkout and compiler path labels
`<repo>` and `<rustc>`. The compiler version and hashes are in `result.json`.

`streams.json.gz` deduplicates identical raw stdout/stderr by SHA-256 and stores
each distinct payload as base64, with a stream-name-to-hash map. Every original
stream is losslessly recoverable and checked against its raw length/hash.
Input and expectation archives restore the `frozen.json` hashes. Output
directories must be new; no original executable is run.

The input-only client takes u64-LE bits plus one RC byte and emits one u64-LE
result. It receives no expectations or fixture path. A partial record or RC
outside 0..3 is rejected before output. The oracle was frozen before Rust;
its unchanged source hash is checked during every reproduction.

## Results and limits

All 137,000 rows match in four native runs (opt0/opt3, two builds each), with
both unit tests passing at each level. There are 34,250 distinct input words,
all 2,048 exponent fields, both signs and four RC values. Fixture generation
also confirms both DAZ interpretations agree for every row. Repeat library,
client and output bytes are identical at each optimization, without masks.

Eight compiled wrong implementations are rejected, with 24–32,884 mismatching
rows each. They cover directed large-value increments, NaN quieting/payloads,
mode sign reversal, half rules and signed zero. Five structural corruptions
below the whole-target hash gate reject body, FDE extent, slot addend and both
constants. These are static mathematical and newly compiled host results;
captured instructions were neither executed nor emulated.

A separate agent reviewed the all-domain arithmetic, bounds and architectural
premises and reproduced the static checker. Native full-domain execution and
compiler correctness are not proved by the finite corpus. Repository/global
test status is reported in `VALIDATION.md`. No acceptance gate, byte-window
counter or whole-node claim changes. The remaining integration question is
which callers establish or rely on a particular MXCSR.RC and exception mask.
