# RE-001: map node #94 WAL record scan loop 0x51628f0

Task: RE-001 (#94 function map). Bounded question: given the buffered
read 0x5162510, what does the scan loop 0x51628f0 do with each record
it reads — how does it assemble fragments, handle compression records,
report errors, and complete into the caller's strings?

- Component: node #94 WAL record scan loop, window
  `0x51628f0..0x5162ec2` (1490 bytes, single FDE 0x13168c0,
  cie=0x1301ae8, LSDA 0xbd8972), plus the buffered-read call contract
  (0x5162510), the reporter call contract (0x5160f90), the body-parser
  call contract (0x5161850) and the detail-builder call contract
  (0x542f040). The callee internals are not pinned here.
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the window bounds, the dispatch table,
  all branch conditions, all report strings and their addresses, the
  append cap, the exit values, the census and the canary slot;
  inference for the +0x71/+0x73 flag readings and the
  out_record/scratch string-object reading; unresolved for the aux out
  word's producer meaning, the setters of +0x70 and +0x73, the parser
  and detail-builder internals beyond the cited PR #1860 pin, the
  consumer of the 0x575b0f8 slot, and the reader struct type name
  (see records.json).
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Relationship to PR #1860: the fragment grammar matches #1860's
  logical reader, but this is a different reader — buffered read
  instead of physical decode, an accumulator internal to the reader
  instead of caller-passed strings, a caller out_record/scratch
  completion protocol instead of #1860's arguments, and extra arms
  (stream-finish prologue, checksum arm with a return-0 exit, error
  arms 10-13, unknown-type arm) that #1860's reader does not have.
  The neighbouring 0x5162350/0x5162510 buffered-reader family was
  judged dependency code in an earlier dry cycle and is used here by
  contract only, not re-submitted.

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; `objdump --dwarf=frames` is not used
  for frames.txt (rows are verbatim from work/fde94/node-94-fde.tsv).

## Answer

`scan(reader, out_record, scratch)` returns an int status. The
prologue initializes out_record to the empty-string constant at
0x1e629b with length 0, clears scratch (first byte 0, length 0), calls
the stream-finish virtual method (vtable +0x18) on reader +0x78 when
non-null, and snapshots the entry remaining (reader +0x60 minus
reader +0x40). It then loops on the buffered read 0x5162510, which
returns a status, a fragment slice, an aux word and a code. Status 0
ends the scan with return 0.

The code dispatches through the jump table at 0x7ee0c8: 1/5 full,
2/6 first fragment, 3/7 middle fragment, 4/8 last fragment, 9
compression, 10-13 error, 15 checksum, 0/14/above-15 unknown type.
Full: reports `partial record without end(1)` when already
in-fragment with a nonempty accumulator, then clears the accumulator,
copies the slice into out_record, writes the entry remaining to
+0x58, sets +0x71, clears the in-fragment flag and returns the read
status. First: reports `partial record without end(2)` when already
in-fragment or the accumulator is nonempty, then replaces the
accumulator with the slice, sets the flag and loops. Middle: reports
`missing start of fragmented record(1)` when not in-fragment, else
appends under the 0x3fffffffffffffff cap (length_error above it) and
loops. Last: reports `missing start of fragmented record(2)` when
not in-fragment, else appends under the same cap, replaces scratch
with the accumulator, moves scratch into out_record, clears the
accumulator, writes +0x58, sets +0x71, clears the flag and returns
the read status. Compression (9): warns `read multiple
SetCompressionType records` when +0x73 is set and
`SetCompressionType not the first record` when +0x71 is set (both
warnings can fire, in that order), clears the accumulator, then for
slices longer than 3 bytes with a first-u32 tag byte of 0 or 7 calls
the body parser 0x5161850, while any other tag or a slice of at most
3 bytes goes through the detail builder 0x542f040 (constant argument
2; per PR #1860's pin the builder writes 2 into the decision byte,
so the `could not decode SetCompressionType record` report is the
branch taken); either way the flag is set and scanning loops. Error
codes 10-13 loop silently when not in-fragment, else report `error
in middle of record`, clear the accumulator and the flag, and loop.
Checksum code 15 clears the accumulator and returns 0 when +0x70 is
set, else reports `checksum mismatch` with the aux word and then
runs the error-arm tail. Unknown codes format `unknown record type
%u` into a 40-byte stack buffer and report it with the slice length
plus the accumulator length when in-fragment, then loop.

The Python model in tools/wal_record_scan.py implements exactly this
state machine with an injectable buffered read, reporter and parser;
tests/test_wal_record_scan.py covers every arm, both warnings, the
cap boundary, the return-0 exits and the packet checks.
