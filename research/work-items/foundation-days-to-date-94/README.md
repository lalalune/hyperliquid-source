# foundation-days-to-date-94: what does the days-to-date checked window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `6fb86319763b30860f92b9da746cbe4f9b637573`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23` was a
  search lead only. No inferred implementation was copied, and no reference
  label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call
  edges; its source-level name and types remain inferences.
- Included: the 75-byte FDE window, its five int3 padding bytes, two incoming
  indirect calls, the outgoing converter call, the expect block with its
  message and source-location record, and the exact unsigned branch gate over
  the u32 input domain.
- Excluded: the converter body at `0x151f870`, the caller beyond its two call
  sites, other time conversions, all #115 addresses, target execution, Rust
  reconstruction, and complete caller behavior.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet connects two actual incoming calls
through a relocated slot to a complete, independently disassembled FDE
window, then follows its range branch and result branch to a private
source-location record. It establishes a concrete small entrypoint for
further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or
test in the tree mentions `0x1450810`, no open pull request title mentions
it or days-to-date/civil conversion, and its bytes overlap nothing in the
hour packet (`0x14509f0`) or the millis packet's calendar helper
(`0x151f6f0`–`0x151f86a`). The converter FDE starts at `0x151f870`, the next
entry after the millis helper's window, so the two packets are adjacent, not
overlapping.

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
python3 tools/foundation_days_to_date.py --check research/work-items/foundation-days-to-date-94/evidence.json
python3 -m unittest tests.test_foundation_days_to_date -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured
service, networked node, chain operation, or model-backed program was
executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x1450810 --stop-address=0x1450860 artifacts/node/94/hl-node
objdump -d --start-address=0x3744020 --stop-address=0x3744547 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `days.objdump.txt` file retains complete disassembly of the window
including its padding. The `caller.objdump.txt` file retains complete
disassembly of the caller FDE window. The `days.frames.txt` file retains
excerpts selecting the FDEs at `.eh_frame` section offsets `0xac74`
(this window), `0x15094` (the converter), and `0x16cdb0` (the caller).
The checker locks these raw FDE records and their shared CIE, and reads
their PC/range fields. It does not add a second general FDE decoder or
replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra
rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`;
the retained `.eh_frame` has equal file offsets and VAs. The tools resolve
sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and the index-stride correction

- `.eh_frame+0xac74` describes `[0x1450810, 0x145085b)`, 75 bytes. GNU's
  independent frame dump agrees. Complete linear decoding from that start
  gives the instruction sequence below, ending exactly at the FDE endpoint.
- The unwind index stride to the next entry is 80 bytes, ending at
  `0x1450860`, only because five `int3` bytes (`0xcc`) pad the window after
  the FDE end. The stride is **not** the FDE extent; any description of this
  window as "80-byte FDE-bounded" would overstate the frame by those five
  padding bytes, and the checker locks the 75-byte body and the padding
  separately.
- A `R_X86_64_RELATIVE` relocation maps slot `0x576f6b8` to `0x1450810`.
  The exact `.text` byte-pattern scan covers 70,370,352 bytes. For `ff 15` /
  `ff 25` whose RIP target is that slot, it finds two candidates,
  `0x374430c` and `0x3744324`, both subsequently visible as instruction
  starts in GNU disassembly from the caller FDE start. For `e8` targeting
  the window it finds zero candidates. Register-indirect references, other
  pointer paths, prefixes, and data sections are not a complete xref census.
- The caller FDE is `[0x3744020, 0x3744547)`, 1,335 bytes. The two call
  sites set `esi` to `0x5a` (90) and `0xe` (14) respectively before calling
  through the slot; the window itself reads only `esi`, so those constants
  are consistent with small day-count arguments but do not by themselves
  prove the caller's argument types.

### Body behavior: one multiply, one unsigned gate, one converter call

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x1450810` | `push rax` | Stack slot |
| `0x1450811` | `mov esi,eax` | Input taken as u32 (zero-extended) |
| `0x1450813` | `imul $0x15180,%rax,%rax` | Days times 86400 |
| `0x145081a` | `movabs $0xffff574000000000,%rcx` | Seconds base |
| `0x1450824` | `add %rax,%rcx` | Computed seconds value, modulo 2^64 |
| `0x1450827` | `movabs $0xfffeae7ffffeae81,%rax` | Unsigned bound |
| `0x1450831` | `cmp %rax,%rcx` | Unsigned comparison |
| `0x1450834` | `jb 0x1450842` | Below bound goes to the expect block |
| `0x1450836` | `call *slot 0x576e8b0` | Converter at `0x151f870` |
| `0x145083c` | `test %eax,%eax` | Converter result test |
| `0x145083e` | `je 0x1450842` | Zero result goes to the expect block |
| `0x1450840` | `pop rcx; ret` | Converter's `eax` returned unchanged |
| `0x1450842` | expect block (see below) | Noreturn path, then `int3` padding |

The converter call passes the entry values of `rdi`, `rsi`, and `rdx`
unchanged, and the computed seconds value in `rcx` (the fourth SysV integer
argument register). Whether the converter reads that register as its own
argument is not decoded here; the register fact itself is retained.

The unsigned gate has an exact threshold over the u32 input domain. The
gap `2^64 - 0xffff574000000000` equals `0xa8c000000000`, an exact multiple
of 86400, and the quotient is exactly `2^31`:

| Input days (u32) | Computed value | Static path |
| --- | --- | --- |
| `0..2147483647` | `0xffff574000000000..0xfffffffffffeae80`, no wrap | Converter call at `0x151f870` |
| `2147483648..4294967295` | Wraps to `0..0xa8bffffeae80`, always below the bound | Expect block at `0x1450842` |

The two inequalities that make the gate exact are checked, not assumed:
the pre-wrap minimum (`0xffff574000000000`) is above the bound
(`0xfffeae7ffffeae81`), and the post-wrap maximum (`0xa8bffffeae80`) is
below it. So within the u32 domain the bound constant never separates two
non-wrapping inputs; the gate is exactly the wrap at `2^31`. The bound
would only matter for inputs wider than u32, which this window cannot
receive because it truncates its input with `mov esi,eax`.

### The expect block and its source-location record

The expect block loads `rdi = 0x219c91`, `esi = 0x22` (34), and
`rdx = 0x566aa80`, then calls through slot `0x576e468` (relocated to
`0x157a9b0`), after which only `int3` padding follows, consistent with a
noreturn path. The data is connected through actual PC-relative
instructions and `R_X86_64_RELATIVE` relocations, not just substring
presence:

| Item | VA | Value |
| --- | --- | --- |
| Message | `0x219c91`, 34 bytes | `` `NaiveDate + TimeDelta` overflowed `` |
| Location record | `0x566aa80` | Path pointer relocated to `0x1e6235`, length 101, line 1909, column 38 |
| Path | `0x1e6235`, 101 bytes | `/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/chrono-0.4.38/src/naive/date/mod.rs` |
| Expect helper slot | `0x576e468` | Target `0x157a9b0` (unnamed here) |
| Converter slot | `0x576e8b0` | Target `0x151f870`, FDE `[0x151f870, 0x151fa9c)` |

The recorded path uses the build's cargo registry prefix; this is target
evidence, not this operator's home directory. The converter's own body,
return type, and error behavior are not decoded in this packet.

## Inferences and unknowns

- **Inferred:** this is a checked days-to-date conversion helper for a
  datetime-like value, with a private chrono `NaiveDate` addition boundary.
  Its u32 day field, seconds multiply, exact `2^31` wrap gate, converter
  call, and overflow message support that label. The binary has no recovered
  symbol name here. Neither the source-level function name nor the full
  input layout, chrono version beyond the registry path, validity invariant,
  or converter return type is proven.
- The `2^31` gate reads naturally as "days must be a non-negative i32", but
  that reading is an inference from the exact threshold, not a recovered
  type: the window itself only ever sees the low 32 bits of its input.
- The two incoming call sites are real indirect calls through the window's
  slot, but the caller's full behavior, its other arguments, and whether
  other callers exist through register-indirect or data paths are not
  closed. The byte-pattern scan is not a complete xref census.
- The converter at `0x151f870` is identified only as the relocated call
  target with its own FDE; calling it "civil-from-days" is an inference from
  its position and this window's date context, not a decoded body. Its
  internal behavior, including what a zero `eax` result means, is unknown.
- The expect helper at `0x157a9b0` is left unnamed: its own library
  ownership, transitive callees, unwind behavior, and non-returning
  behavior are not closed. A private source-location argument does not make
  a generic panic helper private.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence
comparison, normalization mask, behavioral execution, or whole-ELF match is
claimed. All are **not yet implemented/measured**. The raw instruction bytes
in the checker are static evidence locks, not executable reconstruction or
transplanted code. New checker/test/documentation code is independently
authored; imported bytes and disassembly retain the artifact's original
rights.

The repository's required verification, catalogue, and test recipes are run
for this change below; a separate concurrent baseline job in the parent
session is not depended on. After the change, the new checker and the new
unit test pass. The added controls use the authenticated
real target (explicitly skip if LFS is absent), not fabricated behavior
fixtures. They reject:

- wrong identity and truncation;
- changed multiplier, base, or bound bytes;
- changed FDE extent, source line, or relative relocation target;
- changed converter/expect call displacement and an additional direct-call
  pattern;
- changed expect message, relocated slot bytes, and FDE padding bytes.

Structural mutations deliberately bypass only the digest gate in the test
helper, so they exercise downstream checks instead of all failing at
SHA-256. The command-line tool always authenticates the complete target
first.

**No progress gate requested.** Foundation's four gates and generated
progress files stay unchanged. The denominator here is one bounded window /
two call sites, not all time helpers. Next question: decode the converter
body at `0x151f870` far enough to confirm or reject the civil-from-days
reading, then attribute the expect helper at `0x157a9b0` before
reconstructing Rust.
