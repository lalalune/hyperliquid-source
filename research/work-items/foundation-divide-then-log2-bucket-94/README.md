# foundation-divide-then-log2-bucket-94: what does the 114-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 114-byte FDE window, its 14 int3 padding bytes, the divide-then-log2 bucket rule, the one confirmed caller, the no-naming-relocation scan, and the one-direct-caller scan.
- Excluded: the meaning of the quotient (what quantity is divided by what), the caller's behavior beyond the call itself, other bucketing windows, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: an unsigned divide followed by a shift ladder that buckets the quotient into 0..6, with the cap computed arithmetically rather than by a table or a bit-scan. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x4f9eb10`, no open pull request title mentions it or divide-then-log2-bucket, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_divide_then_log2_bucket.py --check research/work-items/foundation-divide-then-log2-bucket-94/evidence.json
python3 -m unittest tests.test_foundation_divide_then_log2_bucket -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4f9eb10 --stop-address=0x4f9eb90 artifacts/node/94/hl-node
objdump -d --start-address=0x4f9cf20 --stop-address=0x4f9d393 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

## Observations

### Window identity

- FDE `[0x4f9eb10, 0x4f9eb82)`, 114 bytes, `.eh_frame+0x28ac3c`, CIE at offset 0, `zR` pcrel sdata4, confirmed with GNU `--dwarf=frames`. The next FDE starts exactly at `0x4f9eb90` (`[0x4f9eb90, 0x4f9eba5)`), so the 14 int3 bytes between the body end and the next FDE start are padding, not body. The checker locks the body and the padding separately.
- Body SHA-256: `6a5f51de0418a80d23313f6f8c849a6058bff5676858fa9a292cd9266b5b5011`.
- Retained disassembly (`window.objdump.txt`):

```text
4f9eb10: endbr64
4f9eb14: xor %edx,%edx
4f9eb16: mov %rdi,%rax
4f9eb19: div %rsi
4f9eb1c: mov %rax,%rcx
4f9eb1f: shr $1,%rcx
4f9eb22: je 4f9eb60
4f9eb24: mov %rax,%rdx
4f9eb27: shr $0x2,%rdx
4f9eb2b: je 4f9eb68
4f9eb2d: mov %rax,%rdi
4f9eb30: shr $0x3,%rdi
4f9eb34: je 4f9eb70
4f9eb36: mov %rax,%rcx
4f9eb39: shr $0x4,%rcx
4f9eb3d: je 4f9eb76
4f9eb3f: mov %rax,%rdi
4f9eb42: shr $0x5,%rdi
4f9eb46: je 4f9eb7c
4f9eb48: shr $0x6,%rax
4f9eb4c: setne %al
4f9eb4f: movzbl %al,%eax
4f9eb52: add $0x5,%eax
4f9eb55: ret
4f9eb56: cs nopw 0x0(%rax,%rax,1)
4f9eb60: xor %eax,%eax
4f9eb62: ret
4f9eb63: nopl 0x0(%rax,%rax,1)
4f9eb68: mov $0x1,%eax
4f9eb6d: ret
4f9eb6e: xchg %ax,%ax
4f9eb70: mov $0x2,%eax
4f9eb75: ret
4f9eb76: mov $0x3,%eax
4f9eb7b: ret
4f9eb7c: mov $0x4,%eax
4f9eb81: ret
```

### Decoded rule

- `xor %edx,%edx` zeroes the div high word, then `mov %rdi,%rax; div %rsi` computes the unsigned quotient `q = rdi / rsi` in rax (remainder in rdx, unused). The divide is the only arithmetic input step: the rest of the window only shifts and tests q.
- `q >> 1 == 0` → `je 0x4f9eb60`: `xor %eax,%eax; ret`, so eax = 0. This covers q = 0 and q = 1, so the rule's low edge is q < 2 → 0, not q == 0 → 0 with a separate q == 1 case. A zero dividend with a nonzero divisor gives q = 0 and returns 0 with no trap.
- `q >> 2 == 0` → `je 0x4f9eb68`: `mov $0x1,%eax; ret`, so q = 2..3 → 1.
- `q >> 3 == 0` → `je 0x4f9eb70`: q = 4..7 → 2.
- `q >> 4 == 0` → `je 0x4f9eb76`: q = 8..15 → 3.
- `q >> 5 == 0` → `je 0x4f9eb7c`: q = 16..31 → 4.
- Otherwise the fall-through computes the cap arithmetically: `shr $0x6,%rax; setne %al; movzbl %al,%eax; add $0x5,%eax; ret`. If q >> 6 == 0 (q = 32..63), setne gives 0 and the result is 5; if q >> 6 != 0 (q >= 64), setne gives 1 and the result is 6. There is no sixth branch: the cap is 5 + (q >> 6 != 0), so every q >= 64 maps to 6.
- Return rule: `eax = 0` when q < 2, else `min(floor(log2(q)), 6)`. Each ladder step re-tests the original quotient (rax is reloaded into rcx/rdx/rdi before every shift), so no step's shift feeds the next; the ladder is five independent tests plus the arithmetic cap, not a narrowing chain.
- No field is written anywhere in the window: every mov is a load or a register-to-register move, and the body contains no store-form instruction. The checker pins all 114 body bytes, so this property follows from the locked instruction list, not from a separate scan.
- Branch targets, all exact: `je` at offset `0x12` (2 bytes, disp `0x3c`) lands on the zero return at offset `0x50`; `je` at offset `0x1b` (2 bytes, disp `0x3b`) lands on the one return at offset `0x58`; `je` at offset `0x24` (2 bytes, disp `0x3a`) lands on the two return at offset `0x60`; `je` at offset `0x2d` (2 bytes, disp `0x37`) lands on the three return at offset `0x66`; `je` at offset `0x36` (2 bytes, disp `0x34`) lands on the four return at offset `0x6c`. Five forward branches, no loop-back branch, no calls inside.
- The `cs nopw` at offset `0x46` (10 bytes), the `nopl` at offset `0x53` (5 bytes), and the `xchg %ax,%ax` at offset `0x5e` (2 bytes) are alignment padding inside the body between return blocks, not separate logic.
- A naive "no 0xe8 byte in the body" call check would be wrong here: the `shr $0x6,%rax` encoding at offset `0x38` (`48 c1 e8 06`) contains an 0xe8 byte that is not a call opcode. The checker therefore tests for a call opcode at instruction starts only, using the locked instruction list.

### Call and data edges

- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` site landing on the window start: `0x4f9d240` (bytes `e8 cb 18 00 00`), confirmed as an instruction start by linear disassembly from its caller FDE start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan.
- Caller FDE: `[0x4f9cf20, 0x4f9d393)`, retained in full in `caller.objdump.txt`. Argument setup observed upstream of the call: `mov $0x80000,%esi` at `0x4f9d21d` and `mov %r14,%rdi` at `0x4f9d222`, with stack stores intervening before the call; the two stores immediately before the call are `movsd %xmm1,-0x90(%rbp)` and `movsd %xmm0,-0x78(%rbp)`. Neither rsi nor rdi is rewritten between the setup and the call, so the call passes rdi = r14 and rsi = 0x80000. The caller's purpose is not claimed.
- Relocations: no record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries).
- Nearest claimed window: tiny tag-swap `0x4f7fb20` (packet #85), `0x1eff0` away.
- Symbol hint, explicitly disclaimed: objdump annotates the address with a nearest ctype `do_widen` label about 0x92f0 bytes below; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

## Inferences

- The "divide-then-log2 bucket" label is an inference from the instruction shape: one unsigned divide, then a shift ladder whose thresholds are exactly the powers of two, capped arithmetically at 6. It is kept separate from the observed rule above.
- The dividend, the divisor, and the meaning of the bucket (what 0..6 indexes or scales) are not identified by the bytes, so no such claim is made.

## Distinction from packet #49

Packet #49 (`0x556e980`, bsr clamp ladder) derives its bucket from a bit-scan-reverse ladder with min/max clamping semantics and an explicit default for the zero input. This window uses different mechanics: an unsigned divide first, then five independent shift tests, then an arithmetic cap (`5 + (q >> 6 != 0)`) with no bit-scan instruction anywhere and no clamp ladder. Same bucket purpose, different mechanism: div + shifts vs bsr. No shared primitive is claimed, and no census of bucketing windows was built.

## Unknowns

- The dividend, the divisor, and the meaning of the bucket values.
- Whether indirect callers or tail jumps reach this window (outside the byte-pattern scan's scope).
- Whether the result is consumed as a bucket index, a scale, or something else.
- The divisor-zero case: the hardware `div` traps on a zero divisor, so no return value exists for that input; it is excluded from the rule rather than assigned a bucket.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
