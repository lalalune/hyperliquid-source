# RE-001: node #115 boolean text-select shim 0x143ddc0

## Bounded question

What does routine `0x143ddc0` (FDE `0x143ddc0..0x143ddf2`, 50 bytes)
do with its two arguments, which memory does it read, and what does it
hand to the routine it tail-calls?

## Answer, pinned to the target

The routine takes a pointer to a one-byte boolean in `rdi` and an
opaque sink pointer in `rsi`. It reads exactly one byte -- the byte at
`(%rdi)` -- selects one of two fixed `.rodata` string operands by that
byte, and tail-jumps (it has no `ret`) through a single `.got` slot,
passing the sink pointer and the chosen `(string, length)` on. The
decision, in order:

1. `mov %rsi,%rax` saves the sink pointer (arg2).
2. `cmpb $0x0,(%rdi)` reads the one boolean byte. The compare is a byte
   compare, so only the low 8 bits matter.
3. `je` on a zero byte takes the **false** arm: `lea` the address of
   `"false"` (`0x479247`) into `rsi`, `mov $0x5,%edx` (length 5), move
   the saved sink pointer into `rdi`, and `jmp *0x64df720`.
4. Any non-zero byte falls through to the **true** arm: `lea` the
   address of `"true"` (`0x459fd8`) into `rsi`, `mov $0x4,%edx`
   (length 4), move the saved sink pointer into `rdi`, and the same
   `jmp *0x64df720`.

The routine never dereferences either string pointer; it only computes
the two addresses with `lea` and passes one on. The two length
immediates (`4`, `5`) equal the byte lengths of the strings their arms
point at, but the routine does not derive them from the strings -- they
are literal operands.

Reads, and nothing else:

| address | width | section | role |
| ------- | ----- | ------- | ---- |
| `(%rdi)` | 1 byte | caller-provided (register-indirect) | boolean selector; `0` -> "false" arm, non-zero -> "true" arm (byte compare) |
| `0x64df720` | 8 bytes | `.got` | indirect tail-jump target; both arms jump through this one slot |

The routine writes no memory, makes no direct call, and has no `ret`.
Its only in-body branch is the single conditional `je` that selects the
arm; control always leaves through one of the two indirect tail-jumps,
both of which target the same `.got` slot. The bytes after the second
tail-jump (`0x143ddf2..0x143de00`, 14 bytes) are `int3` (`0xcc`)
padding, and the next FDE (`0x143de00..0x143de19`) is a separate,
differently-shaped routine.

## String operands, read from the live image

| address | section | bytes | length immediate | arm |
| ------- | ------- | ----- | ---------------- | --- |
| `0x459fd8` | `.rodata` | `true` | `4` | non-zero byte |
| `0x479247` | `.rodata` | `false` | `5` | zero byte |

The string bytes above are read out of the binary by `verify.py`'s
raw-byte emulator (not transcribed by hand): it decodes the `lea`
displacement and the `mov`-immediate length straight from the
instruction bytes, resolves the `.rodata` address, reads `length`
bytes there, and checks they are exactly `true`/`false` with the
immediate equal to the string length.

## How it is reached, and where it tail-jumps (site-only)

There is no direct `call` or direct tail-`jmp` to this routine anywhere
in the executable segment. A pointer to it is installed at load time by
a single `R_X86_64_RELATIVE` record (addend `0x143ddc0`) that writes
the routine's address into `.data.rel.ro` slot `0x63f53d0`.

Both arms tail-jump indirectly through `.got` slot `0x64df720`. That
slot is filled at load time by its own `R_X86_64_RELATIVE` record
(addend `0x167fa70`), so the tail target is the routine at
`0x167fa70` (itself FDE-bounded, `0x167fa70..0x167fe99`). The System V
argument registers at the jump (`rdi` = the sink pointer, `rsi` = the
string address, `rdx` = the length) are the first three arguments of
that callee. What that callee does, and what the sink pointer denotes,
are observed-only and **not** claimed here.

## Negative / corruption controls

`verify.py` runs three controls that must fail on a mutated image,
proving the emulator reads the bytes rather than assuming the answer:

1. Flip the `cmpb` immediate from `0` to `1`: input byte `0` must then
   select the **true** arm (the decoder reads the compare immediate).
2. Corrupt the first byte of `"true"` in `.rodata`: the read string
   must change (the `b"true"` check is load-bearing, not vacuous).
3. Corrupt the false-arm length immediate from `5` to `9`: the decoded
   length must change and must no longer equal the string length (the
   length is read from the bytes and cross-checked against the string).

## NOT claimed

The semantics of the callee at `0x167fa70`; what the sink pointer in
`rsi` denotes (a formatter, a writer, a buffer, or anything else); the
trait or type this shim belongs to; which call sites load the installed
pointer at `0x63f53d0` and invoke it; and the meaning of the adjacent
routine at `0x143de00` (observed to be a distinct fmt-style shim, not
characterised here). The "Display/Debug of a bool" reading these facts
suggest is an inferred label, not part of the claim: the claim is only
the byte-level behaviour above.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x143ddc0 --stop-address=0x143ddf2 work/hl-node-115.bin`.
- `records.json`: semantic records only (arguments, branches, reads,
  string operands, tail-call, census, descriptor context).
- `frames.txt`: the FDE lines for the routine and its neighbour.
  `callers.tsv`: the single reference to the routine (the relocation
  that installs its pointer); there are no direct call sites.
  `relocations.txt`: the two `R_X86_64_RELATIVE` records -- the one
  installing the routine pointer at `0x63f53d0` and the one filling the
  `.got` tail slot `0x64df720` with the callee address `0x167fa70`.
- Census method: the external call/jump census uses the exhaustive
  executable-segment E8/E9 rel32 scan with objdump confirmation; it
  finds zero direct sites. The 8-byte-stride stored-qword scan finds
  exactly one occurrence of the routine address (file offset `0x9898`,
  inside `.rela.dyn`), the addend of the installing `RELATIVE` record.
  The routine's own control transfers are classified from one linear
  disassembly of the whole range: one in-body conditional branch, two
  indirect tail-jumps, zero direct calls, zero direct tail-jumps.
- Model: `model.py` (inside this packet), a direct transcription of the
  disassembly with an enumerated `self_test()` (8 assertions).
- `verify.py` re-checks the digest, the manifest, excerpt regeneration
  byte-for-byte against a fresh objdump run, every excerpt instruction
  byte-for-byte against the raw binary, spot instructions, the int3
  padding, the FDE range, the two relocation records, the empty in-body
  relocation set, the census, the semantic records, the model
  self-test, an independent raw-byte decoder/emulator that resolves the
  string operands and tail target against the live image, and the three
  corruption controls. `census.py` reproduces the census;
  `export_excerpts.py` regenerates `main.txt`.

## Reproduce

Working directory: the repository root. Tools, all from this run:

- GNU objdump (GNU Binutils for Debian) 2.44, invoked as
  `objdump -d --start-address=0x143ddc0 --stop-address=0x143ddf2 work/hl-node-115.bin`
- GNU readelf (GNU Binutils for Debian) 2.44, invoked as
  `readelf --debug-dump=frames work/hl-node-115.bin` and
  `readelf -r work/hl-node-115.bin`
- Python 3 for `census.py`, `verify.py`, `export_excerpts.py` and
  `model.py`
- Input: `work/hl-node-115.bin`, SHA-256 as above (materialised from
  `artifacts/node/115/hl-node` via `git lfs pull`); no execution of the
  target binary, no network, no side effects beyond writing the packet
  files listed in MANIFEST.sha256.

## Verification scope and next step

This packet's own checker (`verify.py`) and the model self-test are run
before submission and print `ALL CHECKS PASSED`. Repository-wide gates
(`make verify`, `make test`, `make catalogue-check`) cover the whole
tree; their results and any pre-existing baseline conditions on this VM
are reported in the PR, not claimed here. The next question is what the
callee at `0x167fa70` does with `(sink, &str, len)` and which sites
load and invoke the installed pointer at `0x63f53d0`.
