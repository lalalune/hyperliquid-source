# RE-001: node #115 gated base-pointer accessor 0x636c880

## Bounded question

What does routine `0x636c880` (FDE `0x636c880..0x636c8b3`, 51 bytes)
return for a given index, which globals gate it, and what does it
leave unread?

## Answer, pinned to the target

The routine takes an unsigned index in `rcx`, makes no calls, writes
nothing, reads exactly two fixed one-byte globals, and returns one
pointer in `rax`. The decision, in order:

1. Read the byte at `0x6713606` (gate A, in `.bss`). The test is
   `cmpb $0x0` + `je`: if the byte is `0`, return `NULL` (`0`). Gate B,
   the index and the base pointer are never consulted on this path.
2. Otherwise read the byte at `0x6717690` (gate B, in `.bss`). The test
   is `cmpb $0x1` + `jne`: unless the byte is exactly `1`, return
   `NULL`. Both tests are byte comparisons, so only the low 8 bits of
   each global matter.
3. Otherwise bounds-check the index with `cmp $0x23,%rcx` + `ja`
   (unsigned above): if the index exceeds `0x23`, return `NULL`.
4. Otherwise return the fixed pointer `0x64ddc20`. The index is never
   used to scale or offset the result -- every in-range index
   (`0..=0x23`, 36 values) yields the same constant pointer.

Reads, and nothing else:

| address | width | section | role |
| ------- | ----- | ------- | ---- |
| `0x6713606` | 1 byte | `.bss` | gate A; `0` forces `NULL` (byte compare) |
| `0x6717690` | 1 byte | `.bss` | gate B; must be exactly `1` or `NULL` (byte compare) |
| `rcx` | 8 bytes | register | unsigned index; must be `<= 0x23` or `NULL`; never indexes the result |

The routine never writes memory, never makes a call, never reads any
offset derived from the index, and never reads the `.data.rel.ro` slot
it returns the address of. All three of its direct jumps land on the
in-body `NULL` block at `0x636c8b0`, so it has no tail jump out and no
landing-pad; the bytes after the final `ret` (`0x636c8b3..0x636c8c0`)
are `int3` (`0xcc`) padding, and the next FDE (`0x636c8c0..0x636c8f3`)
is a separate sibling routine.

## How it is reached, and what it returns (site-only)

There is no direct `call` or tail `jmp` to this routine anywhere in the
executable segment. Instead a pointer to it is installed at load time:
an `R_X86_64_RELATIVE` record (addend `0x636c880`) writes the routine's
address into `.data.rel.ro` slot `0x64ddc18`. The constant the routine
returns, `0x64ddc20`, is the very next qword -- 8 bytes after its own
pointer slot -- and that returned slot carries no relocation of its
own, so it is the address of inline data, not a stored pointer. The
layout of the enclosing record, as observed (not interpreted):

| `.data.rel.ro` offset | content | evidence |
| --------------------- | ------- | -------- |
| `0x64ddc18` | `&routine` (`0x636c880`) | `R_X86_64_RELATIVE` addend `0x636c880` |
| `0x64ddc20` | inline qword `1` (the address the routine returns) | no relocation |
| `0x64ddc28` | `&0x4376fd` (into `.rodata`) | `R_X86_64_RELATIVE` addend `0x4376fd` |

## Negative control: the sibling routine

The immediately following FDE, `0x636c8c0..0x636c8f3`, is the same
byte-gated shape with the same two gate globals but a different base
pointer (`0x64ddb80`) and a different index bound (`0xc3`); its pointer
is installed at `.data.rel.ro` slot `0x64ddb78`, again 8 bytes before
the pointer it returns. It is listed only to show that `0x636c880` is
one member of a family of gated accessors, each bound to its own base
and bound; its semantics are not characterised in this packet.

## NOT claimed

What gate A, gate B or the index denote; what the returned pointer
`0x64ddc20` or the inline data at it means; what consumes the returned
pointer (there is no direct site to attribute it to); the meaning of
the `.rodata` reference at `0x64ddc28`; and the semantics of the
sibling routine or any other family member. Behaviour on an index
whose unsigned value exceeds `0x23` is modelled as `NULL` (the `ja`
path), stated openly.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x636c880 --stop-address=0x636c8b3 work/hl-node-115.bin`.
  The opening `endbr64` (bytes `f3 0f 1e fa`) is a genuine instruction
  in the target, not a placeholder.
- `records.json`: semantic records only (branches, reads, census,
  descriptor context).
- `frames.txt`: the FDE lines for the routine and its sibling.
  `callers.tsv`: the single reference to the routine (the relocation
  that installs its pointer); there are no direct call sites.
  `relocations.txt`: the single `R_X86_64_RELATIVE` record that
  installs the routine pointer at slot `0x64ddc18`.
- Census method: the external call/jump census uses the exhaustive
  executable-segment E8/E9 rel32 scan with objdump confirmation; it
  finds zero direct sites. The 8-byte-stride stored-qword scan finds
  exactly one occurrence of the routine address (file offset
  `0x132eb0`, inside `.rela.dyn`), which is the addend of the
  installing `RELATIVE` record. The routine's own control transfers
  are classified from one linear disassembly of the whole range.
- Model: `model.py` (inside this packet), a direct transcription of
  the disassembly, with an enumerated `self_test()` (52 assertions).
- `verify.py` re-checks the digest, the manifest, excerpt regeneration
  byte-for-byte against a fresh objdump run, every excerpt instruction
  byte-for-byte against the raw binary, spot instructions, the FDE
  range, the relocation evidence, the empty in-body relocation set, the
  absence of a relocation at the returned slot, the census, the int3
  padding, the semantic records, and the model self-test. `census.py`
  reproduces the census; `export_excerpts.py` regenerates `main.txt`.

## Reproduce

Working directory: the repository root. Tools, all from this run:

- GNU objdump (GNU Binutils for Debian) 2.44, invoked as
  `objdump -d --start-address=0x636c880 --stop-address=0x636c8b3 work/hl-node-115.bin`
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
are reported in the PR, not claimed here. The next question is what
gate A (`0x6713606`) and gate B (`0x6717690`) are set to and by whom --
`0x6713606` is a known shared gate byte that appears in other #115
records -- and what reads the pointer this accessor returns, given that
it is reached only through the installed function pointer at
`0x64ddc18`.
