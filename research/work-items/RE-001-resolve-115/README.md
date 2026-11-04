# RE-001: map node #115 resolve-and-cache wrapper 0x5d8cf30 with its default leaf 0x5d8ce80

## Bounded question

Open PR #2403 claims the key-to-value lookup pair and explicitly
leaves this wrapper unclaimed, noting only that the wrapper
"calls the value lookup and stores its result". What does the
wrapper itself do, end to end — which callee does it pick for
which id, what does it store, and what does it return?

## Answer, stated literally

The routine at `0x5d8cf30` (FDE `0x5d8cf30..0x5d8cf6d`) is a
resolve-and-cache wrapper. It takes an object in `rdi` and an
id dword in `esi`, and returns a boolean in `al`.

1. It saves the object in `rbx` and loads the subobject: the
   qword at `obj+0x08`. That subobject — not the original
   object — is passed as `rdi` to both callees below.
2. It tests the id dword (`test %esi,%esi`). Only zero versus
   nonzero matters to the wrapper itself.
3. Zero id (site `0x5d8cf40`): it calls the default leaf at
   `0x5d8ce80` (FDE `0x5d8ce80..0x5d8ce8c`), which returns
   exactly the qword at `subobject+0x118` and writes nothing.
4. Nonzero id (site `0x5d8cf58`): it calls the value lookup
   at `0x5d8ce90`, whose own semantics are claimed by open PR
   #2403 and are NOT re-claimed here: the value lookup takes
   the subobject in `rdi` and the id dword in `esi` and
   returns a value pointer, or 0 on a miss. This packet takes
   that return value as an input.
5. Both arms converge on the same epilogue: the resolved value
   is tested, then stored at `obj+0x10` AND at `obj+0x38`
   (the same value in both slots, including 0 on a miss or a
   zero default), and `setne %al` returns 1 exactly when the
   resolved value is nonzero, else 0. The wrapper writes
   nothing else and makes no other call.

Consequences worth stating plainly: a miss and a zero-valued
hit are indistinguishable from the wrapper's return and its
stored slots — both leave 0 in both slots and return 0. The
wrapper never reads `obj+0x10` or `obj+0x38` before writing
them, so a previous cached value is unconditionally
overwritten. The wrapper's own id test means an id whose low
32 bits are zero takes the default arm, whatever its upper
bits held on entry (the `esi` register carries only the dword).

## How the wrapper is reached

The wrapper has NO direct call and NO tail jump anywhere in
the binary (whole-file census, reproduced by the packet's
`census.py`). Its only whole-binary occurrence is a single
`R_X86_64_RELATIVE` relocation: slot `0x64c9bc8` in
`.data.rel.ro`, with addend `0x5d8cf30` (see
`relocations.txt`). At load time that slot is filled with the
wrapper's address, so the wrapper is reached through that
function-pointer slot, not by a direct call. The raw-byte scan
in `census.py` reports one "stored qword" at file offset
1069888 (`0x105340`): that is the addend field of the
relocation entry itself inside the `.rela.dyn` section, not a
data pointer — the distinction is recorded here so the census
line is not misread as a second reference. Which table owns
slot `0x64c9bc8`, and which consumer loads it, is NOT
claimed: no direct call site identifies the consumer.

## The default leaf's other call sites

The leaf at `0x5d8ce80` has ten direct calls in total (whole-
file census): the wrapper's zero-id arm plus nine other sites,
recorded by address and caller function in `callers.tsv`
only. No caller semantics beyond the wrapper arm are claimed
for those nine sites.

## Verification

Run from the repository root:

    python3 research/work-items/RE-001-resolve-115/verify.py
    python3 tests/test_resolve_115.py

`verify.py` prints ALL CHECKS PASSED after checking: the work
binary digest against the provenance entry; `MANIFEST.sha256`
against every packet file; excerpt regeneration byte-for-byte
against a fresh objdump run
(`objdump -d --start-address=0x5d8cf30 --stop-address=0x5d8cf6d work/hl-node-115.bin`
and the same for `0x5d8ce80..0x5d8ce8c`); every excerpt
instruction byte-for-byte against the raw binary; three spot
instructions byte-for-byte against a fresh objdump run and the
raw binary, plus three extra spot instructions checked the
same way during this cycle (`0x5d8cf40`, `0x5d8cf60`,
`0x5d8ce8b`); the FDE ranges against a fresh frame dump; the
census (wrapper: 0 calls, 0 jumps, 1 RELATIVE addend, the
single relocation-entry qword; leaf: 10 calls, 0 jumps, 0
stored qwords, 0 RELATIVE addends); the semantic records; and
the model tests.

Instruction mnemonics such as `endbr64` in the excerpts are
genuine instructions present in the target binary, not
placeholders: the excerpts are verbatim objdump output, kept
whole-function, and every instruction in them is checked
byte-for-byte against the raw binary.

## Environment limits, stated honestly

This work was done on a VM with no cargo/rustc, no git-lfs
and no Ghidra/Java, using only objdump/readelf static
analysis of the digest-verified node #115 work binary
(SHA-256 `a6e2897c…5301`, `work/hl-node-115.bin` hashes
exactly against `provenance/artifacts.json`). No meaning is
assigned to the object, its subobject, the ids or the values
beyond their field offsets; no runtime behavior was observed.

## Not claimed

See `records.json`: what the fields denote, the value
lookup's internals (open PR #2403), the owning table of slot
`0x64c9bc8` and its consumer, caller semantics beyond the
census, and anything past the wrapper's return.
