# l1-shared: reconstruct the node #115 f64-to-decimal conversion (0x5c43c60 and its caller 0x43099f0)

With this packet the whole float-to-decimal conversion of node #115 can be rewritten as a plain function: a 96-bit mantissa and binary exponent go in, a sign/scale/96-bit decimal (or a refusal) comes out, including the 28-digit scale clamp, the half-up rounding of the digit trims, the f32/f64 significant-digit limits and the refusal rule for large values, and its f64 caller 0x43099f0 splits the float bits, rejects non-finite values and builds the same result; an independent Python specification agrees with the executed bytes on 13,310 cases and 57 of 57 negative controls are detected.

- Component ID: l1-shared (shared numeric helper; callers seen in the perp/spot code paths, not owned here)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main at 0781ce04826eeefd89fe336cb8ea073be0c1de30; no reference source was copied
- Claim status: observation (executed bytes versus specification, call graph, coverage) / inference (the role names below) / unresolved (the three helpers behind GOT slots)
- Scope included and excluded: included are the two function bodies 0x5c43c60 (1,453 bytes, 402 instructions) and 0x43099f0 (502 bytes, 126 instructions), all four flag combinations of the converter, the caller's value-tag, parse-error, non-finite, zero, denormal and free branches. Excluded are the value reader (slot 0x64e95c0), the string-to-f64 parser (slot 0x64e0048), the temporary drop 0x42320d0, the deallocator (slot 0x64df4a0), the panic helpers, and every caller of 0x43099f0. No progress gate is requested.

## Reproduce

Run from the repository root; the tool and the test use only the standard library and `tools/fde_extents.py` / `tools/decimal_scaled_u64.py`. It never runs the binary.

```
python3 tools/decimal_from_f64_115.py --out research/work-items/l1-shared-f64-to-decimal-115
python3 -m unittest tests.test_decimal_from_f64_115
sha256sum -c research/work-items/l1-shared-f64-to-decimal-115/MANIFEST.sha256
```

The tool checks the input SHA-256 first and fails on any other binary. One `--out` run takes about two minutes and stays far below 1.5 GB. Output files: `kernel_cases.tsv` (every 11th converter case), `caller_cases.tsv` (the first 30 and every 12th caller case), `controls.tsv`, `coverage.tsv`, `calls.tsv`, `measure.json`. All numbers come from ELF bytes read with `struct` (sections, FDE extents, instruction boundaries, slot values); no disassembler output is parsed.

## Evidence

Coordinates are virtual addresses of the loaded image. FDE extents were read from `.eh_frame`: 0x43099f0..0x4309be6 and 0x5c43c60..0x5c4420d.

### The converter 0x5c43c60

Arguments (System V): `rdi` result, `rsi` pointer to three u32 mantissa words (low, middle, high), `edx` binary exponent, `cl` positive flag, `r8b` "f64" flag, `r9b` "round" flag. Result at `rdi`: u32 tag (1 success, 0 refusal), u32 flags (`scale << 16`, bit 31 for negative), u32 high word, then the low and middle words as one u64.

1. Exponent above zero (0x5c43c7f..0x5c43d1d): each of the `edx` steps either doubles the mantissa and decreases the exponent-ten counter, or, when bit 95 is set, divides by 5 and leaves the counter alone. A positive counter afterwards means multiply by 10 that many times (0x5c43de0); a carry out of 96 bits returns the refusal (tag 0).
2. Exponent below zero (0x5c43d22..0x5c43dc8): each of the `-edx` steps multiplies an odd mantissa by 5 when the product still fits in 96 bits, otherwise halves it and raises the counter; an even mantissa is halved and raises the counter.
3. Counter at or below -29 (0x5c43e31..0x5c43f43): divide by 10 with round-half-up (remainder above 4, carry propagated through the three words) until the counter is -28; a value that has fallen below 10 becomes zero with scale 0.
4. Counter below zero and `r9b` set: with `r8b` set the mantissa is divided with rounding until it is below 2^52 (high word zero and middle word below 0x100000), without `r8b` until it is below 2^24; the counter reaches 0 whenever the loop divides all the way. When the limit is met first, trailing decimal zeros are stripped, each strip raising the counter, using a multiply-by-inverse divisibility test.
5. Epilogue (0x5c441ac): flags = `-(counter << 16)` with bit 31 set when `cl` is zero.

The three `call` instructions (0x5c441ed, 0x5c441fa, 0x5c44207) reach overflow panic helpers for `dec`/`inc` of the counter; `coverage.tsv` shows they were never reached.

### The caller 0x43099f0

Arguments: `rdi` result, `rsi`/`rdx` string pointer and length. Its call sites (`calls.tsv`): the value reader through slot 0x64e95c0, the string-to-f64 parser through slot 0x64e0048, the converter 0x5c43c60 (direct, with `r8d = r9d = 1`), the temporary drop 0x42320d0, the free through slot 0x64df4a0 (twice, the second in the landing pad), and the unwind resume.

- Value tag 6 copies the 16 payload bytes to the result with tag 0x1a2 and skips parsing.
- Otherwise the string is parsed; a parse error gives tag 0xb0. Non-finite bits (magnitude at or above 0x7ff0000000000000) give tag 0xb0.
- Normal numbers: low word = low 32 fraction bits, middle word = high 20 fraction bits | 0x100000, exponent = biased - 1075; denormals: the fraction words with exponent -1074; zero: a decimal built from the sign bit and 12 constant bytes at 0x4553c4 / 0x4553cc (all zero in this image). The positive flag is `bits >= 0` as a signed value.
- A converter refusal (tag not 1) gives tag 0xb0; success gives tag 0x1a2 and the 16 decimal bytes.
- At the end the buffer of the first value is freed (`free(r15, r14, 0)`) unless its tag is 1..4 or the pointer word is zero. The tag-6 branch returns before this check.

### Coverage

`coverage.tsv`: 377 of 402 converter instructions and 112 of 126 caller instructions were executed. The converter's unexecuted instructions are the three panic arms, two alignment `xchg`/`nop` forms, the success exit of the multiply-by-ten loop (0x5c43e18..0x5c43e2c) and the third carry arm of the round loop (0x5c43f06..0x5c43f10 for the 64-bit trim, 0x5c44068 loop entry). The caller's unexecuted instructions are the landing pad 0x4309bbb..0x4309be1.

## Implementation and comparison

`tools/decimal_from_f64_115.py` holds the evaluator subclass, an independent specification (`spec_kernel`, `spec_caller`), the case generators and the controls. The specification is written from the listing and shares no code with the evaluator; the caller is executed for real including the converter call, and only the four GOT/drop/free calls are replaced by recorded stubs whose arguments are compared with the specification's expected trace.

Case classes (converter, 11,510 cases): tiny, f64_small, f64_mid, f64_wide (|exponent| up to 1,100), f32 (24-bit mantissas), wide_mantissa (96-bit), round_edge (digit patterns around half), multiply_overflow, clamp_edge (exponents -128..-165), carry_edge (the quotient plus one carries across words) and scale_edge (results at scale 28/29). Caller: 1,800 cases with edge float bit patterns first (zero, one, denormals, maximum, infinities, NaNs) and then random patterns, all value tags 0..9, parse errors and null buffers.

Negative controls (57): 28 wrong specifications (18 for the converter, 10 for the caller), 21 single-byte corruptions of the real code (compare constants, jump conditions, flag arguments, exponent bias, success tag), 6 out-of-range inputs and 2 damaged input binaries. A control counts as detected when the corrupted object disagrees with the unmodified specification or the tool refuses it.

## Results and limitations

`measure.json`: 13,310 cases (11,510 converter, 1,800 caller), 0 mismatches, 2,025 converter refusals among the cases, 57 negative controls, 57 detected. Tests: `python3 -m unittest tests.test_decimal_from_f64_115` (known values such as 0.1 -> mantissa 1 scale 1, refusal cases, free rule, controls, manifest and coverage consistency).

Limits:

- Everything is observation of executed bytes; the names (converter, caller) are inferences from the argument shapes and results. The converter resembles the usual base-2 to base-10 conversion of Rust decimal libraries, but that was not checked against any source.
- The multiply-by-ten success exit (0x5c43e18..) was not reached. Inference: after a divide-by-5 step the value is already at least 2^95/5, so multiplying by 10 cannot stay below 2^96; the exit looks unreachable, not proven.
- The three panic helpers for counter overflow were not reached; the counter never leaves the range of an i32 for the allowed inputs.
- The value reader (0x64e95c0), string parser (0x64e0048), temp drop (0x42320d0) and deallocator are modelled only by their observed arguments, not reproduced.
- No gate is requested: this is one numeric helper and its f64 caller, not a component.

Next question: who calls 0x43099f0 with a string (the deserializer for decimal-typed fields), what the value reader behind slot 0x64e95c0 returns for tags 0..5, and the drop 0x42320d0.
