# RE-001: one node #115 native fsync argument/result boundary

- Component: function-map research supporting storage/persistence (RE-009).
- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Repository baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Status: static observations; ownership, source type names and helper semantics unresolved.
- Scope: one FDE-backed boundary, not an fsync/fdatasync chooser or storage implementation.

## Reproduce

From the repository root, with the pinned Git LFS artifact materialized:

```sh
python3 research/work-items/RE-001-node115-file-durability-boundary/verify.py
python3 -m unittest discover -s tests -p test_node115_file_durability_boundary.py -v
objdump -d -w --start-address=0x6019690 --stop-address=0x601976c artifacts/node/115/hl-node
readelf -W --debug-dump=frames artifacts/node/115/hl-node | grep -A14 '^007550ec'
```

Observed local tools: Python 3.11.11 (GCC 12.2.0), GNU binutils 2.40,
Linux x86-64 isolated runner. The verifier uses only Python's standard library;
it reads the capture, authenticates its full digest, parses ELF sections,
dynamic relocation/symbol/string tables, the selected FDE and aligned instruction
encodings. It does not execute the capture or invoke a network service.
`boundary.json` records the exact body and FDE SHA-256 values and replay fields.
`boundary.disasm.txt` is the original bounded GNU objdump output (220 target bytes),
not reconstructed source. Its nearest-symbol banner does not name this function.

## Evidence

All instruction addresses below are image VAs, not runtime load addresses.
The ELF is PIE. `.text` VA/file mapping differs by `0x1000` here; the selected
VA interval `[0x6019690,0x601976c)` maps to file `[0x6018690,0x601876c)`.
The `.eh_frame` section-offset record `0x7550ec` (length field `0x3c`,
CIE `0x730230`) covers exactly that interval. GNU readelf independently reports:

```text
007550ec 000000000000003c 00024ec0 FDE cie=00730230 pc=0000000006019690..000000000601976c
```

This is an unwind extent, not a claim of all reachable code or helper closure.
The exception landing path at `0x6019760` jumps outside the extent to
`0x6019664`; that path is not analyzed further.

### Descriptor and nonnegative return path

- `0x6019699`: entry `rsi` saved in `rbp`; `0x601969d`: entry `rdi` saved in `rbx`.
- `0x60196a4`: `edi = DWORD [entry_rsi+0x4c]`.
- `0x60196b7`: direct call to `0x63f1640`, whose PLT indirect jump resolves
  to GOT `0x64ee770`. `.rela.plt` binds that slot to dynsym 401, `fsync`,
  through `R_X86_64_JUMP_SLOT` (addend zero).
- `0x60196bc`: `test eax,eax`; `js` at `0x60196be` targets `0x60196f8`.
  The actual predicate is negative versus nonnegative, not equality to zero.
- On the nonnegative path, stores zero to DWORD `[rbx]`, WORD `[rbx+4]`,
  and QWORD `[rbx+8]`. The normal epilogue returns `rbx` in `rax`.

The input is consistent with a descriptor-bearing object and an output object,
but their source-level types and the zeroed fields' meanings are not established.
This packet does not implement or simulate a filesystem durability guarantee.

### Negative return path

- `0x60196f8`: direct call to `__errno_location@plt` at `0x63f0ad0`.
- `0x6019708`: `ecx = DWORD [rax]`; `rdx = entry_rsi+0x28` at `0x601970a`;
  `rdi = entry_rdi` and `rsi` references a local string object.
- Immediate stores construct the 11-byte text `While fsync`, with a NUL
  terminator and length 11. The overlapping little-endian stores are retained
  in the excerpt; the verifier checks their exact encodings.
- `0x601973a`: calls `0x6018080` with those arguments. The helper's behavior,
  returned error representation, exception behavior and mutation of the output
  are not inferred from its name or guessed from a reference implementation.
- Cleanup calls `0x63f0d80` (objdump labels `_ZdlPvm@plt`) if the local string
  storage differs, then rejoins the epilogue. The canary failure call is
  `0x63f0d70` (`__stack_chk_fail@plt`). These two labels and the errno label
  are disassembler observations; only the fsync PLT/GOT/dynsym chain is fully
  parsed by this verifier. No helper-closure claim is made.

## Implementation and controls

This is independently authored offline evidence tooling, not a Rust equivalent
or a source-reconstruction result. No copied inferred `can1357` code, normalized
byte matching, transplanted implementation bytes or build-identity claim.
No catalogue, component, byte-coverage registry or progress gate is changed.

The local run executed 14 unittest methods and passed all 14 in 2.286 seconds.
The recorded target replay also exited zero. Controls mutate the descriptor
load, call displacement, negative branch, success stores, errno call, error
context, literal, helper call, FDE range, PLT displacement and relocation slot.
An additional method rejects ten altered evidence fields; target truncation
fails full-digest authentication. Low-level byte controls deliberately bypass
the full-digest layer to exercise the structural/instruction checks themselves.
They do not execute mutated binaries and do not claim robustness against every
malformed ELF. The exact verifier stdout is reproducible from `boundary.json`.

Required independent repository and global checks are separate from this local
proof; their actual receipts must be reported with any submission. This local
record is not a statement that CI or the full suite has passed.

## Results and limitations

Validated denominator: one selected FDE extent, 220 bytes, five direct call
instructions within that extent, and one fsync import-resolution chain. This is
not an exhaustive caller count, component map, comparison percentage or gate.
An initial bounded static search found candidate raw call bytes for both
fsync and fdatasync; raw byte matches were not treated as aligned callers.
Only this selected aligned boundary was promoted to durable evidence.

Unknown: callers and dispatch/selector relationship, object ownership and
layouts beyond observed offsets, dependency provenance, error helper semantics,
exception cleanup closure and whole-node behavior. No node, visor or live-chain
execution occurred. RE-001 and RE-009 full-scope acceptance gates remain false.

Next question: which actual aligned caller supplies this object's descriptor
and chooses this boundary rather than an fdatasync path? This packet does not
answer that question or request a gate for it.
