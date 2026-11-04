# RE-001: Node115 stat-file FD cache lifecycle

Component: foundation (research allocation; original crate ownership unknown).
Target: Linux x86-64 hl-node #115,
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/tools base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

## Question and new evidence

How does the retained #115 target initialize its file-descriptor budget, admit
or discard a descriptor, and replace a cached descriptor after reading a stat
file? This packet joins the initializer and both budget consumers to one actual
parent path. It is static research, not a reproduced product defect or a Rust
implementation. No gate change is requested.

All addresses below are unrebased ELF VAs. Seven complete `.eh_frame` FDE
extents are retained in spec.json with CIE/LSDA identities and full instruction
bytes. FDE coverage does not prove complete original source-function boundaries.

## Observations

- `0x5cbae40..0x5cbaee9`: calls the actual `getrlimit` relocation with raw
  resource7. A failed call selects512. Otherwise it copies the returned hard
  limit to the soft field, attempts `setrlimit(7, ...)`, selects the post-call
  soft value on result0 or the saved old soft on failure, then shifts right1.
  It allocates32 bytes and stores qwords1,1,0,budget. Allocation/panic targets
  remain outside semantic closure; the allocation is not an established Rust type.
- `0x5cce8d0..0x5ccea0a`: after lazy lookup/lock/poison checks, the ordinary
  return path increments the qword at object+0x18 with a signed overflow guard.
- `0x5ccea10..0x5ccebdf`: the ordinary unpoisoned path admits a descriptor only
  with a signed-positive budget and decrements it. Nonpositive/poison paths
  unlock, invoke the actual `close` import, and return raw-1. Lock slow paths,
  panic-state checks, poison state and unwind behavior are not fully recovered.
- `0x5cb51f0..0x5cb5334`: builds a path using literal `stat` at0x45a16c,
  calls the open/read contexts below, and calls admission at0x5cb52ac only
  after a non-error read result. It then checks the prior cached32-bit descriptor
  against-1, returns its budget via slot0x64e10a8, closes it, and stores the new
  admission result. The read buffer is returned even if admission returned-1.
  Earlier open/read error branches do not run this replacement sequence.
- `0x5cc9c00..0x5cc9c47`: lazy-force context constructs stack closure arguments
  including global+8, then dispatches through another indirect helper. The data
  initializer slot0x64fedd0 resolves to0x5cbae40. This does not close the entire
  lazy implementation or establish a source crate/version.
- `0x5ccfe00..0x5ccff40` and `0x5cceea0..0x5ccef9f`: full open-path and
  seek/read contexts called by the parent. They include long-path, allocation,
  read, errno and cleanup branches. Their indirect helper semantics are pending;
  their instruction bytes are retained without pretending helper closure.

`getrlimit`, `setrlimit` and `close` identities come from actual `.rela.dyn`
and `.dynsym`, not an assumed PLT order. The Linux generic UAPI resource header
labels7 RLIMIT_NOFILE (reference: torvalds/linux v6.12,
include/uapi/asm-generic/resource.h); this does not identify the captured build's
kernel or headers. Rust Arc/Mutex, sysinfo and process-stat-cache source labels
are hypotheses, not recovered dependency identities. No external inferred source
was copied, and no original first-party ownership or exact compiler is claimed.

## Reproduce

Materialize and authenticate the repository's pinned #115 artifact first.
Use Python3.11+ with Capstone5 and native GNU objdump (tested5.0.7 reported
wrapper from the retained5.0.9 distribution, GNU binutils2.47, Python3.12.1):

```sh
python3 research/work-items/RE-001-node115-stat-fd-cache/verify.py \
  --objdump /absolute/path/to/objdump --output work/stat-fd-cache
make doctor
make verify test catalogue-check
make reproduce
```

The verifier parses target bytes/FDEs/relocations, runs objdump only as a data
reader, and compares all selected address/raw-byte instruction pairs against
Capstone and the retained record. Each objdump subprocess has a30-second limit.
No captured code, emulator, networking or resource-limit syscall is executed.
Output paths are chosen explicitly; the operator used a bounded Windows Job
supervisor. GNU text exports canonicalize display filenames, line endings and trailing
whitespace only; instruction and operand content is not normalized. Original
unmodified operator exports and the first diff-check refusal remain retained
outside the packet.

Eight corruption controls attack target identity, bounds, instruction payload,
resource anchor, parent literal, import identity and initializer relocation.
They validate evidence rejection, not modeled behavior or source equivalence.

## Results, limitations and next question

See verification.json and MANIFEST.sha256 for actual reproduction and payload
hashes. The denominator is seven selected FDE extents only. Compiled source
comparisons:0; reconstructed implementation bytes:0; whole-component denominator
unmeasured. Data, transitive callees, lock/poison/panic behavior, exact dependency
source/build identity and whole-ELF equivalence remain unresolved. All component
gates remain false. Retained raw disassembly is evidence, never transplanted code
for an implementation. Required repository-check outcomes are reported in the PR.

Next question: bind the stat-reader's outer caller to an actual node service and
close its path/open/read and lazy-init helpers before selecting licensed source
or claiming behavior equivalence. This packet does not claim integrated node
startup, current-network compatibility, a source-built component or a security bug.
