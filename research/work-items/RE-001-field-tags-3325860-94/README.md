# RE-001: field-name tag selector at 0x3325860

**Question:** For node #94, what result does the entire function at
`0x3325860` produce from its input byte span? **Answer:** Given a writable
output pointer in `rdi`, a readable byte pointer in `rsi`, and length in
`rdx`, it writes `09 00` for the eight bytes `app_hash`, `09 01` for the
21 bytes `hot_user_to_signature`, and `09 02` for every other length or
byte sequence; it returns the original output pointer in `rax`. The two
bytes are stores at offsets 0 and 1 (offset 1 is written first). Input
pointers need only be readable on the relevant length path, and output
must be writable. This is a static, byte-level rule, not a target execution.

## Identity and boundaries

- Component: RE-001 function map; field names suggest a serialization
  context, but the owning type and component are unproven. Target: node #94,
  SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json). Source checkout: `e5c9b6436876b2a4a39daef813171f9879317699`;
  no reference source was used to infer this rule.
- Virtual-address window: `0x3325860..0x33258c2`, size **98** bytes;
  body SHA-256 `fdf64f4bbeb10be76e16c87f93f303d7247f66968877a9f291fc198f3adcb219`.
  FDE `.eh_frame+0x114848`, length 0x10, CIE `.eh_frame+0x0`;
  its decoded PC range equals the window. **14** `cc` padding bytes
  follow to the next FDE start `0x33258d0` (next FDE at `+0x11485c`).
- Counts from `records.json`: **0 callees**, **1 e8 caller candidate**,
  **0 e9 jump candidates**, **4 branches**, **2 constant blocks**.

## Observations and inference

The complete byte-checked instruction walk is in `instructions.txt`.
The first length comparison sends 21 to two unaligned 16-byte loads; the
second sends 8 to an eight-byte equality comparison against the immediate
`app_hash`. Other lengths go straight to the fallback without reading
`rsi`. For length 21 the loads cover bytes 0..15 and 5..20. The
RIP-relative constant blocks are `hot_user_to_sign` at `0x206bc0` and
`ser_to_signature` at `0x203b80`: their overlap is consistent. The two
`pcmpeqb` results are ANDed lane-wise and `pmovmskb` must equal `0xffff`,
so every byte of both overlapping loads must match, exactly establishing
`hot_user_to_signature`. All three exits store tag byte 0, 1, or 2 at
`[rax+1]`, then 9 at `[rax]`, and return. There are no calls, indirect
branches, or external writes other than the output. The instruction walk
includes every instruction in the FDE window and resolves all branch and
constant targets.

The full `.text` byte-offset scan for unprefixed `e8`/`e9` rel32 patterns
found the single `e8` candidate `0x2cb0613` and no `e9` candidates. Focused
instruction inspection shows the former is a call at an instruction
boundary: `e8 48 52 67 00`, preceded by output, pointer and length setup.
The scan is intentionally over every byte, not a claim that every possible
candidate is an instruction; it cannot enumerate indirect calls, references
in data, prefixed forms, or other executable sections. The scan found only
one candidate, whose focused instruction context was inspected. No enclosing
source type, full parser, error behavior, or owner is asserted.

## Novelty check

Before investing in the bind, from the repository root, both commands
returned no output (exit status 1):

```sh
rg -i '3325860|53631072' research/
rg -i '3325860|53631072' ../../hl-re1-base/{open_prs,merged_prs,closed_unmerged_prs}.txt
```

There are no callees whose behavior is bound. The decimal number is the
function start; searches include both forms. After this packet is added,
the first search naturally finds this packet.

## Reproduction and controls

The generator and verifier use Python 3.10+ standard library, ELF section
metadata, authenticated bytes, and a strict complete instruction decoder;
they do not invoke an external disassembler. The decoder accepts only the
recorded instruction encodings, checks short-branch targets and their
instruction boundaries, decodes signed RIP-relative displacements, checks
both 16-byte constants, FDE PC/CIE/extent and padding, and scans `.text`.
`records.json` contains semantic facts; the complete instruction walk is
separate. `verify.py` requires an explicit manifest whitelist and compares
regenerated evidence with the packet. The independent Python rule model is
exercised against exact names, one-byte mutations at every position, nearby
lengths and arbitrary values; these are consequences of the decoded bytes,
not differential executions. Corruption controls reject an incorrect digest,
modified instruction, FDE location, caller target, records and manifest.

```sh
python3 tools/field_tags_3325860.py --out research/work-items/RE-001-field-tags-3325860-94/
python3 -m unittest tests.test_field_tags_3325860 -v
python3 research/work-items/RE-001-field-tags-3325860-94/verify.py
make verify
make catalogue-check
```

Exploration used GNU objdump 2.44 and readelf 2.44 on the authenticated
binary; committed evidence and tests do not depend on either. Static reads
only; no node/visor execution or networking. `make doctor` reported Python
3.13.5 and native binutils available. See the contribution report for actual
repository-wide check results below.

`make verify` stopped on the node #115 Git LFS pointer;
`make catalogue-check` stopped with a byte-coverage target identity mismatch.
The no-network constraint prevented fetching missing artifacts. `make test`
encountered an unrelated missing reference file `references/can1357-hl/l1/abci/state.rs`
and was interrupted early; it did not complete. The focused
packet tests and verifier passed.

## Limits and next step

The two numeric tags and constant prefix are observable bytes, not proven
source enum identities or a wire-format claim. Address range and the direct
caller alone do not establish first-party ownership. Invalid pointers,
aliasing between input and output, exceptional machine conditions, indirect
xrefs, data/relocations, and behavior in other releases are outside the
model. This is no reconstructed Rust or binary-equivalence result and does
not advance any full-component gate. Next, bind the surrounding caller's
input construction and downstream consumption to identify the enclosing
field/type and establish whether these tags appear in a serialized format.
