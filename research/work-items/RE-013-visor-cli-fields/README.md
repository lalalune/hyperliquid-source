# RE-013: visor argument declarations and raw extraction fields

- Component: `visor`; source base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Target: `artifacts/visor/captured/hl-visor`, 8,305,392 bytes, SHA-256
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Question: which bytes declare the two argument names, which numeric
  settings accompany them, and which raw words/byte are written by the
  extraction body?
- Status: bounded static observations and explicitly limited interpretation.
  No captured executable is run and no component gate is requested.

The two scoped FDEs are `0x5b5690..0x5b5e1a` (1,930 bytes) and
`0x5b9070..0x5b92a6` (566 bytes). They are outside the startup thunks/runtime
handoff in [#978](https://github.com/lalalune/hyperliquid-source/pull/978) and
the lifecycle ranges in [#45](https://github.com/lalalune/hyperliquid-source/pull/45),
frozen head `c8c98b76ccf883fa4aa7aca9c4a4ccc8a8e00692`. Consumption of these
outputs, downloads and child behavior remain outside this packet. Separate
stopped GPG-command research is preserved and not reused.

## Reproduce

From a checkout with the authenticated visor and pinned repository inputs:

```sh
mkdir -p work/visor-cli
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/visor_cli.py \
  --output work/visor-cli/record.json
cmp research/work-items/RE-013-visor-cli-fields/record.json \
    work/visor-cli/record.json
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  research/work-items/RE-013-visor-cli-fields/check_listings.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_visor_cli.py -v
```

The producer is standard-library-only and uses the unchanged project
`elf_index.sections` / `fde_extents.fde_extents` readers. Its public entry
checks the complete size/hash before parsing. The private `_derive` seam
lets corruption tests exercise guards below that outer digest check; there
is no CLI re-pin option. A record is fully derived before exclusive output
creation, preserving earlier evidence on refusal.

`BOUNDARY-AUDIT.json` records both actual GNU objdump 2.44 commands and raw
listing hashes. For example:

```sh
objdump -d -M intel --show-raw-insn --insn-width=16 \
  --start-address=0x5b9070 --stop-address=0x5b92a6 \
  artifacts/visor/captured/hl-visor
```

Both full FDE extents were decoded linearly: 399 instruction rows / 2,496 raw
bytes. Every row is compared with target file bytes, adjacent rows tile the
two ranges, and all 12 selected control windows start/end on decoded
boundaries. Symbol-like nearest-address annotations printed by objdump do
not establish helper names. The record derives actual targets from encoded
operands and RELATIVE relocations. No Ghidra profile or guessed load base is
used; coordinates are linked ELF VAs with file offsets supplied.

## Observations

1. **The same two names occur in declarations and extraction.** The three
   adjacent, explicitly bounded slices are `hyperliquid-visor` (17 bytes,
   `0xb72b5`), `skip-download` (13 bytes, `0xb72c6`) and `child-args`
   (10 bytes, `0xb72d3`). No NUL-termination rule is assumed. Extractor
   `0x5b9070` copies the application-name bytes, invokes slot
   `0x7e76e0 -> 0x5b5690`, then invokes slot `0x7e69f0 -> 0x478c40`.
   The first selected relocation binds the two owned bodies directly;
   complete semantics of the surrounding generic helpers remain external.
2. **The constructor writes distinct numeric settings.** Within its first
   name region, `0x5b5996` obtains `skip-download`; the following stores use
   stack slots `+0x1e0` / `+0x1e8` for the pointer / length 13, and the
   dword store at `0x5b59c9` writes `0x404` to `+0x210`. The same pointer
   and length are also stored at `+0x230` / `+0x238`. In the second region,
   `0x5b5c5f` obtains `child-args`, pointer / length 10 go to `+0x680` /
   `+0x688`, and `0x5b5c92` writes `0x426` to `+0x6b0`. These are transient
   machine-level fields and numeric values. Their individual bits are not
   assigned parser-policy names.
3. **One lookup return is retained as a raw byte.** At `0x5b90f6`, the
   extractor supplies `skip-download` with `edx=13` to `0x5d3220` and
   copies its `eax` return into `ebp` at `0x5b910a`. Later `0x5b923d`
   stores `bpl` to `[rbx+0x18]`, with `rbx` copied from incoming `rdi`.
   The normal-return def-use interpretation assumes the called helpers
   preserve ABI callee-saved registers; that contract is not runtime-tested.
   This does not establish the helper's accepted syntax, return domain or
   original Rust field type.
4. **The child-name search includes a concrete byte equality check.**
   The zero test of qword `[rsp+0x298]` branches to `0x5b91ee`. Otherwise
   `0x5b912f` calls `0x626760` with the name and length 10. The following
   search-like sequence checks candidate length 10 and compares eight bytes
   against inline `child-ar`, plus two bytes against `gs`, by XOR/OR before
   the equality branch `0x5b91be -> 0x5b920a`. The hash/lookup helper and
   complete table invariants remain external; a full search algorithm or
   private table layout is not recovered.
5. **A fallback block writes three observed words.** Block
   `0x5b91ee..0x5b920a` writes `(0,8,0)` to stack offsets `(0,8,16)` then
   jumps to `0x5b923d`. It is reached by the initial zero test and another
   selected nonzero-mask branch at `0x5b91dc`. The sequence is recorded as
   raw words; its pointer validity, container representation and Rust type
   are not established.
6. **The other shown route delegates collection and joins the same stores.**
   `0x5b920a` loads two words at candidate-relative offsets `-0x18` and
   `-0x10`, computes `first + second*24` in machine-width arithmetic, and supplies a temporary record
   with the relocated pointer `0x7e6aa0 -> 0x48dc00` to `0x61da10`.
   At `0x5b923d..0x5b925a`, the raw stack words `(0,8,16)` are copied to
   output offsets `(0,8,16)`, alongside the retained lookup-return byte at
   offset 24. Complete helper behavior, ownership, element types, padding
   and the full output ABI remain unknown.

The argument-declaration/extraction interpretation is supported by the
application-name context, repeated exact name references and bound call
between the two bodies. This is a partial static field contract. Accepted
trailing or multiple arguments, positional/option distinctions, quoting,
UTF-8/error handling and downstream effects are not inferred from these
observed settings or field stores.

## Controls and limits

Eleven focused tests regenerate the real packet and reject whole-artifact,
setting, name/key, fallback/output/branch, relocation and FDE-range
corruptions. The listing comparator independently rejects a wrong instruction
byte even when its listing hash is re-pinned, and rejects a false total.
Real CLI controls cover spaced paths, prior-output preservation and failed
input without publication. They never invoke the captured program or its
parser.

The explicit scope is two FDE ranges with 12 selected windows, four name
references, six selected calls and five selected branches. These are not
complete CFG, call, branch or matched-function denominators. There is no
source reconstruction, runtime equivalence, new native-provider analysis or
completion gate. All visor component gates remain false.

Next question: establish the `0x5d3220` lookup return contract and the
constructor-setting interpretation against their actual generic helpers
before assigning public CLI semantics to the observed fields.
