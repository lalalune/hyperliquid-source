# RE-012: node115 concrete file-open options and write/close lifetime

Component: foundation; task RE-012. Sole target Linux x86-64 node #115,
105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Original ELF VAs,
no rebasing, byte normalization, captured execution or instruction emulation.
New project-authored research and scripts are MIT.

## New bounded question

Which actual open options does `0x5ca5110..0x5ca53a1` produce, how do they
reach `open64` on both path-conversion arms, and what happens to the descriptor
and result across open failure, write failure, empty data and close?

The existing `RE-009-abci-state-export-115` already describes the **write
loop**: partial progress, zero-write error, interrupt retry and impossible
count failure. Those shared 657 bytes are retained as context, not offered
again as new loop discovery or byte coverage. This packet closes its formerly
open **option producer/open helper, long-path callback and normal close-result
policy**, with the full concrete call/data/relocation chain.

Live PR inventory inspected on 2026-11-04 found no competing complete
file-open lifecycle outcome. The existing export packet explicitly calls its
producer an “open-like helper” and does not identify these flags/mode or the
returned close value's treatment. No issue was opened, drafted or claimed.

## Concrete option production

Entry arguments are path pointer/length in RDI/RSI and data pointer/length
in RDX/RCX. The writer saves the data pointer in R14, remaining length in RBX,
and path length in R15 before path conversion. At `0x5ca5130..0x5ca5156`
it constructs exactly 14 option bytes at `rbp-0x38`:

```
00 00 00 00 b6 01 00 00 00 01 00 01 01 00
```

| Offset | Observed value | Inferred field, validated by the open helper's uses |
| ---: | ---: | --- |
| +0, dword | 0 | Custom flags |
| +4, dword | 438 / 0666 | Creation mode |
| +8 | 0 | Read |
| +9 | 1 | Write |
| +10 | 0 | Append |
| +11 | 1 | Truncate |
| +12 | 1 | Create |
| +13 | 0 | Create-new |

These names are interpretations of the actual operand uses, not an assumed
public Rust layout. The complete open helper is `0x5c97060..0x5c97226`.
For this concrete byte record, it selects access value 1, combines the
truncate bit shifted by nine with creation bit 0x40, masks custom flags with
`0xfff7fffc`, then ORs **0x80000**. The observed final call arguments are:

```
open64(nul_terminated_path, 0x80241, 0666)
```

Under the Linux x86-64 flag interpretation this is write/create/truncate
with close-on-exec. The **numeric bytes and final arguments** are the target
facts; no actual OS permission, successful truncation, process umask or
filesystem state is observed here. Other option combinations have distinct
validation branches in the retained helper. This outcome does not claim a
general reconstructed OpenOptions API from this one concrete producer.

`verify.py` reprojects this fixed 14-byte layout from its pinned immediate
stores and checks the selected flag/mode arithmetic. It is a fixed static
data-layout consequence, not an instruction evaluator or runtime oracle.

## Short and long paths reach the same open contract

Paths of at most **383 bytes** are copied into the 384-byte local region,
followed by an appended zero. A first NUL at exactly the original length
admits the direct open-helper call. Interior NUL instead constructs tag 1
with static error pointer `0x64c2fb8`, whose retained literal is
`file name contained an unexpected NUL byte` and kind byte is 20.
No descriptor was obtained on that branch, so neither write nor close runs.

The longer-path arm supplies callback `0x5c810e0..0x5c81101` to adapter
`0x5c78c10..0x5c78cc8`. The context is a pointer to the same local options
record. The callback projects that options pointer and the converted C-string
pointer into the **same `0x5c97060`** helper; it does not invent a second
open policy.

The adapter's real conversion slot `0x64df718` -> `0x141e960` allocates,
copies and checks the path. Its success sentinel is signed-minimum; the
finalizer `0x64df690` -> `0x141e170` appends zero and returns the owned
C-string allocation. On normal callback completion, the adapter clears its
first byte, releases that allocation and returns the callback's output
record. Conversion failure yields the same static NUL error, releasing any
failed conversion buffer. Selected landing pads retain owned-path cleanup.
Allocator, slice-validity and arbitrary exceptional effects stay boundaries.

## Open retry and result ownership

The open helper calls imported **open64**, identified by its dynamic symbol
and actual relocation at `0x64ec8c8`. A return other than -1 gives output tag
0 and the descriptor dword at +4. A return of -1 reads imported
`__errno_location`, encoding the value as `(u32 errno << 32) | 2`.
Only error integer **4** disposes of that temporary error and retries the
same pathname, flags and mode. Other integers give output tag 1 and the saved
error at +8. No descriptor is owned by the writer on that failed-open route.

On a successful result, the writer loads the descriptor into R15D and only
then examines data length. Thus **zero data length still opens using the
same options**, then bypasses `write` and reaches close. The call is not
skipped merely because the data buffer is empty. This is a conditional code
ordering observation, not an executed file modification.

## Retained write result survives close

The already-studied loop supplies the descriptor, current R14 pointer and
RBX remaining count to imported `write`. A positive admitted count advances
both; error integer 4 retries without changing them. Other write errors use
the encoded native error. A zero return while bytes remain selects static
pointer `0x64c39a8`; its exact retained message is
`failed to write whole buffer`, with kind byte 23. A count above remaining
reaches the bounds/failure helper and `ud2` if it returns; it is not accepted
as normal write progress.

All normal owned-descriptor exits join `0x5ca534c` with the **selected write
result already in R13**. Success, including empty data, sets R13 to zero.
The next instructions call imported close with R15D and then execute
**`MOV RAX,R13`**. Therefore, under the normal ABI/callee-return contract:

| Prior result | Descriptor action | Returned result |
| --- | --- | --- |
| NUL/open error | No close; no acquired descriptor | Path/open error |
| Successful open, no bytes to write | One close call | Zero |
| All bytes written | One close call | Zero |
| Write-zero or non-interrupt write error | One close call | The selected write error |

The **close return value is ignored**: it is not inspected, converted through
errno, retried or substituted for the saved write result. This conclusion
comes from the actual call and immediate R13-to-RAX move, not an assumed
standard-library contract. It does not establish flush/fsync, durable data,
atomic publication or successful close. No additional “failure report” is
inferred from that call. The selected unwind landing pad also calls close
before `_Unwind_Resume`; this is not a proof that every arbitrary external
exception route is closed.

`flow.json` records the exact source/destination fields and branch outcomes.
No rollback guarantee is introduced: opening and writing may have effects
before a returned error under the actual external OS contract.

## Evidence and qualification

Eight complete FDEs total **2337 bytes / 673 instructions**: writer,
open-options helper, long-path adapter, concrete callback, CString
constructor/finalizer, error destructor and overreported-count boundary.
These are export denominators, not reconstructed bytes or extra credit for
shared contexts. `records.json` binds full body hashes, actual FDE/CIE bytes,
LSDA addresses, 40 calls, 105 branch records, relative/data bindings and five
real dynamic symbols: `open64`, `write`, `close`, `__errno_location`, `memcpy`.
Imported interposition and arbitrary helper effects remain explicit.

GNU and LLVM objdump agree with Capstone on every instruction byte; GNU
readelf independently confirms all FDEs. Only LLVM's separate LOCK row is
joined to its contiguous instruction. No bytes are normalized. Actual
versions are retained in `tools.json`; options are preserved in `collect.py`.

```sh
python3 -B research/work-items/RE-012-file-write-lifecycle-115/collect.py --out work/fresh-file-write-export
diff -u research/work-items/RE-012-file-write-lifecycle-115/records.json work/fresh-file-write-export/records.json
python3 -B research/work-items/RE-012-file-write-lifecycle-115/verify.py --out work/fresh-file-write-check.json
```

The focused verifier freshly reproduced the record; rejected **36 actual
instruction corruptions, four literal/error-record corruptions, seven
RELATIVE-addend mutations, five imported-writer mutations and two
wrong/truncated capture controls**; and rechecked the concrete options and
flag/mode arithmetic. The narrow checks detect their corruptions without
relying on the whole-file identity guard. These are static qualification
counts, not executed I/O/differential cases. `qualification.json` records
actual outcomes; parent publication owns repository/catalogue checks.

## Boundaries

No captured process, instruction interpreter, filesystem operation or network
was run. No Rust implementation, peer runtime, hosted CI, container result or
whole file-publication pipeline is claimed. The allocator, OS effects,
interposition, pointer/layout validity, full unwinder and generic helper
termination remain open. This result closes the concrete option/open/normal
close lifecycle of this writer, leaving all 92 component gates and registered
byte-comparison totals unchanged. Source-built integration requires real
licensed error/path/OS dependencies and separately authorized execution;
mock syscall responses alone would not establish filesystem compatibility.
