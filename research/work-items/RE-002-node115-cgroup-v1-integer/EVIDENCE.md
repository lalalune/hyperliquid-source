# RE-002: node #115 cgroup V1 integer admission

- Component: `foundation`; CPU-count initialization.
- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
- Status: static observations and stated semantic inferences. No target execution.
- Scope: the V1 quota/period integer reader after a successful text read, its
  Unicode trim, and the call/result boundaries of the file reader.

## Gap and method

The existing `RE-002-cpu-quota-115/CONTRACT.md` leaves text parsing unresolved.
It identifies the V1 helper at `0x5ba9f00`, but does not establish its accepted
grammar. This packet resolves that bounded question. It does not change the
existing Rust numeric projection or recover the whole CPU initializer.

The collector reuses the repository's ELF reader, FDE decoder, instruction
decoder and native-output parser. No new general analysis tool or test suite
is introduced. The interpretation comes from target instructions and data;
no inferred source, upstream implementation or captured code was copied into
an executable implementation.

## Reproduce

Work from the repository root with materialized Git LFS inputs and the pinned
submodules. Python 3.10+, Capstone 5.0.7 and GNU binutils are required.

```sh
python3 -B research/work-items/RE-002-node115-cgroup-v1-integer/collect.py \
  --check --out work/cgroup-v1-integer-replay
```

Use a fresh output directory. `--check` compares the regenerated structured
records and the instruction bytes of the retained native exports. The script
also compares each fresh GNU instruction partition with Capstone and checks
the three FDE ranges with GNU readelf. GNU text formatting and version changes
do not need to produce identical display text.

The recorded run used Windows AMD64, CPython 3.12.0, Capstone 5.0.7 and GNU
objdump/readelf 2.30. `qualification.json` contains exact commands and versions.
Only static parsing and disassembly ran. No captured instruction, emulator,
file-reader syscall, cgroup query, network service or chain operation ran.

## Addresses and boundaries

All addresses below are linked ELF virtual addresses. The text mapping puts
these bodies at file offset `VA - 0x1000`. Data addresses use their own section
mapping; do not apply that subtraction to the whitespace table or filenames.

| Role | FDE range, exclusive end | Bytes | Instructions |
| --- | --- | ---: | ---: |
| V1 integer helper | `0x5ba9f00..0x5baa07d` | 381 | 116 |
| File-read boundary | `0x5baa080..0x5baa18b` | 267 | 64 |
| Unicode trim | `0x5baa6f0..0x5baa987` | 663 | 175 |

The complete FDE-described ranges total 1,311 bytes and 355 instructions.
`frames.txt`, the three `.objdump` files and `records.json` retain native
extents, byte hashes, raw FDE/CIE records, branches, calls and RIP references.
All branches inside each range land on decoded instruction boundaries.
An FDE describes unwind coverage; it does not prove complete function or
component ownership. Split bodies and code without unwind records remain gaps.

## Observations: caller and reader

At `0x5ba9185`, the initializer supplies the literal `cpu.cfs_quota_us` from
`0x4531b0`, length 16, to the call at `0x5ba9197`. It requires RAX equal to one
and retains RDX as the quota in R12. The second call at `0x5ba91be` receives
`cpu.cfs_period_us` from `0x93ee26`, length 17. It also requires RAX equal to
one. The subsequent `test rdx,rdx` rejects a parsed zero period before the
floating calculation. The whole argument/result window is pinned in the
collector. These are V1 call sites; the V2 `cpu.max` route is not this parser.

The helper calls `0x5baa080` with an output record on its stack. It applies
NEG/JNO to the first returned word. The sole overflowing word is
`0x8000000000000000`; that path returns tag zero. Otherwise it passes the
pointer and length from record offsets 8 and 16 to trim at `0x5ba9f3d`.
Nonzero capacity causes a cleanup call through slot `0x64df4a0`, resolved to
`0x635de30`. The failure payload in RDX is unspecified and must not be read.

The file reader resolves slots `0x64e0b58` and `0x64ebff8` to `0x5c89400` and
`0x5ca8380`. It calls `0x5baaa90` and uses the `close` import at `0x64dfe78`.
The two reader error paths publish the sentinel above. Successful completion
copies its three-word result to the caller. Those call boundaries, cleanup
edges and LSDA call-site records are retained. Path joining, file opening,
I/O errors, UTF-8 validation, exception personality and allocation behavior
inside those callees remain unresolved. The grammar below assumes a successful
read containing valid UTF-8; it does not claim invalid UTF-8 admission.

## Observations: trim and integer loop

The trim body scans forward and backward by UTF-8 codepoints. It accepts
U+0009 through U+000D and U+0020 directly, checks U+1680 and U+3000 explicitly,
and uses a 256-byte table for the remaining whitespace checks. The actual
RELATIVE relocation at `0x64dfc30` points to table VA/file offset `0x479266`.
Its SHA-256 is
`2479482c1d14bb27cb07be6eb893aaf994aa096f8318804b68a8d18b0a23ff3f`.

Bit zero admits U+0085 and U+00A0. Bit one, for the U+20xx page, admits
U+2000 through U+200A, U+2028, U+2029, U+202F and U+205F. The exact union is
25 codepoints, recorded in `records.json`. U+001C, U+200B and U+FEFF are not
members. The table only classifies the ends of the string; interior spaces
still reach the integer digit check.

An empty trimmed slice returns tag zero. A one-byte `+` or `-` also returns
tag zero. At `0x5ba9f8a`, only an initial ASCII `+` advances the pointer and
reduces the digit count. The helper does not accept a negative sign.

For fewer than 17 digits after the optional `+`, `0x5ba9fd0` checks each byte
by subtracting ASCII `0` and comparing the unsigned result with nine. It
accumulates `value * 10 + digit` with LEA. The maximum 16-digit result is
below 2^64, so this branch needs no arithmetic overflow exit.

For 17 or more digits, `0x5baa015` uses unsigned MUL and JO to reject an
overflowing product. The following ADD records carry with SETB. The digit
check rejects non-ASCII digits, and the saved carry rejects an overflowing
sum. Completion at `0x5baa054` sets tag one; R12 supplies the value in RDX.
Length 17 selects checked arithmetic; it is not a maximum length. Arbitrary
leading zeros can keep the running value inside u64.

## Inferences and boundary examples

On the stated successful-valid-text domain, the observed path is equivalent
to: remove the listed whitespace at both ends; accept an optional ASCII `+`;
require at least one ASCII decimal digit; return the integer only if it fits
in u64. These examples are deductions from the instructions, not measurements
of the captured node and not a frozen runtime oracle.

| Text after successful read | Inferred parser result | Reason |
| --- | --- | --- |
| Empty text or whitespace only | Tag 0 | Empty trimmed slice |
| `+` or `-` | Tag 0 | Lone-sign branch |
| `-1` or `-0` | Tag 0 | Minus fails the ASCII digit check |
| `+00042` | Tag 1, value 42 | Optional plus, leading zeros |
| `0` | Tag 1, value 0 | Zero is a valid integer here |
| `18446744073709551615` | Tag 1, u64 maximum | Neither multiply nor add overflows |
| `18446744073709551616` | Tag 0 | Final add carries |
| `184467440737095516150` | Tag 0 | Final multiply overflows |
| 40 zeros followed by `1` | Tag 1, value 1 | No fixed decimal-length limit |
| `1 2`, `1_000`, `0x10`, `max` | Tag 0 | Interior non-digit byte |
| U+00A0, `42`, U+3000 | Tag 1, value 42 | Both ends are target whitespace |
| U+001C, `42`, U+001C | Tag 0 | U+001C is outside the target table |

A parsed zero quota differs from a parse failure. The initializer's separate
publication guard suppresses a zero quota, as the prior packet records.
A parsed zero period instead leaves the arithmetic path at `0x5ba91cd`.
Unlimited V1 text `-1` fails this unsigned parser; it is not converted to
u64 maximum. This packet does not establish V2 `max` handling.

## Qualification and limits

The positive replay authenticates the whole image, pins selected instructions,
filenames and table bytes, checks the relocation, decodes complete ranges,
rejects loader relocations that overlap selected code/data, and compares GNU
and Capstone partitions. Twelve independent corruptions
are rejected: sign, digit limit, length split, multiply overflow, add carry,
quota call, filename, two table entries, table relocation, FDE extent and image
identity. The first eleven bypass only the outer whole-image digest check,
so the reported failures exercise the inner evidence checks.
`controls.json` records every changed file offset and rejection reason.

Repository validation on this packet's source base:

- `make doctor`: analysis ready; Rust and LLVM/Ghidra are not available.
- `make verify`: passed after restoring LF bytes in the fresh submodules and
  using an ASCII temporary directory for Git's MSYS GPG. Source pins did not
  change. Both captured artifact signatures passed.
- `make catalogue-check reproduce`: passed with `PYTHONUTF8=1`.
- Existing `test_cpu_quota_115_static.py`: all 10 tests passed.
- Fresh packet replay: passed with normal Python and with `-O`.
- `make test`: failed on unchanged Windows-specific output comparisons.
  `test_abci_state_export115.py` reported 17 LF/CRLF mismatches;
  `test_action_tag_serialize_115.py` reported one path-separator mismatch.
  The run was stopped while starting file 39 of 1,052, after those failures.
  A separate run of the latter file with UTF-8 enabled reproduced the path
  mismatch: 12 tests ran, one failed. The complete suite did not finish.
  Hosted Linux CI and a full Linux suite are not claimed as passed.

Windows commands used GNU `mingw32-make.exe` with `PYTHON=python`, an isolated
Python environment containing the CI-pinned Capstone/pytest versions, Git's
`usr/bin` on PATH, and `TEMP`/`TMP` pointing to an ASCII directory. The initial
default-codepage catalogue check failed; enabling UTF-8 fixed that environment
error without changing repository code. Raw local logs are retained under
ignored `work/cgroup-quota-validation/`. `validation.json` records commands
and actual outcomes; there is no claim that the full suite passed.

This is static research, not a Rust implementation or an execution comparison.
No source body, normalized byte window, whole-module denominator, runtime
output, network compatibility or complete component gate is claimed. No
normalization mask is used. The four component gates remain false.

The next question is whether the unresolved read-to-text boundary validates
UTF-8 before producing the successful record and how its error reaches the
initializer without publishing a CPU quota.
