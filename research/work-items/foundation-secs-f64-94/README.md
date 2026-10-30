# foundation-secs-f64-94: what does the seconds-as-f64 window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: can1357/hl was a search lead only. No inferred implementation
  was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call
  edges; its source-level name and types remain inferences.
- Included: the 115-byte FDE window, its thirteen int3 padding bytes, the
  outgoing helper call, the single incoming indirect call, the borrow
  normalization, the microsecond scaling arithmetic, the f64 divisor, and
  the two overflow paths.
- Excluded: the helper body at `0x151d1b0`, the caller beyond its call site,
  other time conversions, all #115 addresses, target execution, Rust
  reconstruction, and complete caller behavior.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet binds one small window directly after
the hour window (`0x14509f0`): a straight-line conversion whose constants
pin its units without any deep decode. The borrow threshold is exactly
1,000,000,000, the scale is exactly 1,000,000, the sub-second divisor is
exactly 1,000 (proven by checking the magic division against truncating
division on positive, negative, boundary and extreme samples), and the
result divisor is exactly the double 1,000,000.0. It establishes a concrete
small entrypoint for further reconstruction without declaring the component
mapped.

This window was checked for overlap before building: no work-item, tool, or
test in the tree mentions `0x1450a60`, no open pull request title mentions
it or seconds-as-f64, and its bytes overlap nothing in the hour packet
(`0x14509f0`), the days packet (`0x1450810`), or the millis packet's
calendar helper (`0x151f6f0`–`0x151f86a`). The helper FDE starts at
`0x151d1b0`, far from the millis helper's window, so the two packets are
unrelated.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python
3.12.3, GNU objdump 2.42 (Binutils for Ubuntu), GnuPG 2.4.4. The checker and
tests use Python's standard library only. No llvm-objdump, Ghidra, or Java
was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in
CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_secs_f64.py --check research/work-items/foundation-secs-f64-94/evidence.json
python3 -m unittest tests.test_foundation_secs_f64 -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured
service, networked node, chain operation, or model-backed program was
executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x1450a60 --stop-address=0x1450ae0 artifacts/node/94/hl-node
objdump -d --start-address=0x44aa5a0 --stop-address=0x44ab560 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window
including its padding. The `caller.objdump.txt` file retains complete
disassembly of the caller FDE window. The `window.frames.txt` file retains
excerpts selecting the FDEs at `.eh_frame` section offsets `0xad24`
(this window), `0x14df4` (the helper), and `0x56aba0` (the caller).
The checker locks the window and helper FDE records and their shared CIE,
and reads their PC/range fields. It does not add a second general FDE
decoder or replace RE-001. The caller FDE uses a different CIE, so the
checker locks only its call-site bytes and slot displacement, not its
frame record.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra
rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`;
the retained `.eh_frame` has equal file offsets and VAs. The tools resolve
sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and the index-stride correction

- `.eh_frame+0xad24` describes `[0x1450a60, 0x1450ad3)`, 115 bytes. GNU's
  independent frame dump agrees. Complete linear decoding from that start
  gives the instruction sequence below, ending exactly at the FDE endpoint.
- The unwind index stride to the next entry is 128 bytes, ending at
  `0x1450ae0`, only because thirteen `int3` bytes (`0xcc`) pad the window
  after the FDE end. The stride is **not** the FDE extent; any description
  of this window as "128-byte FDE-bounded" would overstate the frame by
  those thirteen padding bytes, and the checker locks the 115-byte body and
  the padding separately.
- A `R_X86_64_RELATIVE` relocation maps slot `0x576f6c8` to `0x1450a60`.
  The exact `.text` byte-pattern scan covers 70,370,352 bytes. For `ff 15` /
  `ff 25` whose RIP target is that slot, it finds one candidate,
  `0x44ab1b2`, subsequently visible as an instruction start in GNU
  disassembly from the caller FDE start, where the next instruction
  (`ucomisd` on `%xmm0`) is consistent with this window returning an f64.
  For `e8` targeting the window it finds zero candidates.
  Register-indirect references, other pointer paths, prefixes, and data
  sections are not a complete xref census.
- The caller FDE is `[0x44aa5a0, 0x44ab55b)`, 2,651 bytes. The caller beyond
  its call site is not analyzed.

### Body behavior: one helper call, one borrow, two scalings, one division

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x1450a60` | `push rax` | Stack slot |
| `0x1450a61` | `call *slot 0x576eaa0` | Helper at `0x151d1b0` |
| `0x1450a67` | `test %rax,%rax; sets %sil` | Whole field negative? |
| `0x1450a6e` | `test %edx,%edx; setg %cl` | Sub-second field positive? |
| `0x1450a73` | `and %sil,%cl` | Borrow = (whole < 0) and (sub > 0) |
| `0x1450a76` | `movzbl %cl,%esi; add %rax,%rsi` | Whole + borrow |
| `0x1450a7c` | `imul $0xf4240,%rsi,%rax` | Whole seconds times 1,000,000 |
| `0x1450a87` | `jo 0x1450ac9` | Multiply overflow goes to the shared tail |
| `0x1450a89` | `lea -0x3b9aca00(%rdx),%esi` | Sub minus 1,000,000,000 |
| `0x1450a8f` | `test %cl,%cl; cmove %edx,%esi` | Borrowed sub, else original sub |
| `0x1450a94` | `movslq %esi,%rcx` | Sub-second field, sign-extended |
| `0x1450a97` | `imul $0x10624dd3,%rcx,%rcx; shr/sar; add` | Signed division by 1,000 (magic, verified) |
| `0x1450aae` | `add %rcx,%rax` | Total microseconds |
| `0x1450ab1` | `seto %cl; test; jne 0x1450ac9` | Add overflow goes to the shared tail |
| `0x1450ab9` | `xorps %xmm0,%xmm0; cvtsi2sd %rax,%xmm0` | Microseconds as f64 |
| `0x1450ac1` | `divsd 0x20ae60,%xmm0` | Divide by the double 1,000,000.0 |
| `0x1450ac9` | `andpd 0x202ed0,%xmm0` | Shared tail: abs mask on a zeroed register |
| `0x1450ad1` | `pop rax; ret` | f64 seconds returned in `%xmm0` |

The helper call passes the entry values of `rdi`, `rsi`, and `rdx`
unchanged. After the call, only `rax` and `edx` are used: `rax` is the
whole-second field and `edx` (the low 32 bits of `rdx`, sign-extended) is
the sub-second field. Whether the helper returns this pair or the window
reads entry state the helper preserved is not decoded here; the register
facts themselves are retained.

The arithmetic pins the units. The borrow threshold is exactly
1,000,000,000, so the sub-second field is in nanoseconds. The whole field
is scaled by exactly 1,000,000 and the sub-second field is divided by
exactly 1,000, giving total microseconds, and the final division by exactly
1,000,000.0 gives f64 seconds. The sub-second division truncates toward
zero (the magic-division check covers negative samples), so the result is
truncated to microsecond resolution, not rounded:

| Input (whole, sub) | Computed value | Returned |
| --- | --- | --- |
| `(0, 0)` | 0 microseconds | 0.0 |
| `(-1, 500000000)` | Borrow: 0 whole, -500,000,000 ns → -500,000 microseconds | -0.5 |
| `(2, 1500)` | 2,000,000 + 1 microseconds | 2.000001 |
| `(0, -1500)` | -1 microsecond (truncation toward zero) | -0.000001 |
| `(1, -1)` | 1,000,000 + 0 microseconds | 1.0 |
| `(-2, -2500)` | -2,000,000 + -2 microseconds | -2.000002 |

### The overflow paths return +0.0

Both overflow paths converge on the shared tail at `0x1450ac9`. On the
multiply-overflow path, `%xmm0` was zeroed by `xorpd` at `0x1450a83`
before the `jo` branch; on the add-overflow path, `%xmm0` is still that
same zero (the `xorps` at `0x1450ab9` is skipped by the `jne`). The tail
applies the absolute-value mask `0x7fffffffffffffff` at `0x202ed0` to
+0.0, which stays +0.0. So neither overflow saturates nor produces NaN:

| Input (whole, sub) | Overflow | Returned |
| --- | --- | --- |
| `(9223372036855, 0)` | Whole times 1,000,000 exceeds i64 | +0.0 |
| `(9223372036854, 2147483647)` | Whole times 1,000,000 fits, plus 2,147,483 exceeds i64 | +0.0 |

## Inferences and unknowns

- **Inferred:** this is a seconds-as-f64 conversion of a (whole seconds,
  nanoseconds) pair, with microsecond truncation and a +0.0 overflow
  result. Its whole-plus-borrow scaling, exact 1e9 borrow threshold, exact
  1e6/1e3/1e6 constants, and f64 return support that label. The binary has
  no recovered symbol name here. Neither the source-level function name
  nor the helper's contract, nor the type that owns the pair, is proven.
- The helper at `0x151d1b0` is identified only as the relocated call
  target with its own FDE (`[0x151d1b0, 0x151d33f)`); its body, return
  contract, and error behavior are not decoded in this packet.
- The single incoming call site is a real indirect call through the
  window's slot, but the caller's full behavior, its other arguments, and
  whether other callers exist through register-indirect or data paths are
  not closed. The byte-pattern scan is not a complete xref census.
- The `edx` field is read only as the low 32 bits of `rdx`; if the helper
  returns a wider sub-second value, the window's view of it is truncated
  to i32, and that truncation is part of the observed behavior, not a
  claim about the helper's type.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence
comparison, normalization mask, behavioral execution, or whole-ELF match is
claimed. All are **not yet implemented/measured**. The raw instruction bytes
in the checker are static evidence locks, not executable reconstruction or
transplanted code. New checker/test/documentation code is independently
authored; imported bytes and disassembly retain the artifact's original
rights.

The repository's required verification, catalogue, and test recipes are run
for this change below. After the change, the new checker and the new unit
test pass. The added controls use the authenticated
real target (explicitly skip if LFS is absent), not fabricated behavior
fixtures. They reject:

- wrong identity and truncation;
- changed scale, borrow, or division-magic bytes;
- changed FDE extent, divisor, or overflow mask;
- changed helper/incoming call displacement and an additional direct-call
  pattern;
- changed relocated slot bytes and FDE padding bytes.

Structural mutations deliberately bypass only the digest gate in the test
helper, so they exercise downstream checks instead of all failing at
SHA-256. The command-line tool always authenticates the complete target
first.

**No progress gate requested.** Foundation's four gates and generated
progress files stay unchanged. The denominator here is one bounded window /
one call site, not all time helpers. Next question: decode the helper body
at `0x151d1b0` far enough to state what pair it returns, before
reconstructing Rust.
