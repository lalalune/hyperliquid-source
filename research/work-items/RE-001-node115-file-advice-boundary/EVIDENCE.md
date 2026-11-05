# RE-001: node115 bounded file-advice native boundary

- Component ID: storage (prospective native dependency only; original crate ownership unresolved).
- Target: node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/base commit: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Status: static observations; file-advice wrapper is an inferred descriptive label, not a recovered original symbol.
- Included: one entire native FDE, its five table-selected advice legs and outgoing thunk/PLT/relocation chain.
- Excluded: other callers, original source attribution, storage schema/replay, return semantics at callers, target execution and all gate completion.

## Reproduce

From repository root, with the pinned artifact already materialized:

```sh
python3 research/work-items/RE-001-node115-file-advice-boundary/verify.py
python3 -W error::ResourceWarning tests/test_node115_file_advice_boundary.py -v
```

Observed environment: Python 3.11.11; GNU objdump/readelf (Debian Binutils) 2.40; Linux x86-64 isolated runner. The script reads ELF data, invokes `objdump -d -M intel --insn-width=16` for the selected range, and streams `readelf --debug-dump=frames --wide`. It never loads or executes node115. Outputs: `verified.json` and `verified-disassembly.txt`; exact objdump arguments are in JSON. Run/output hashes are recorded in `run-results.json`. No network, chain interaction, signing or paid data.

## Evidence

The exact FDE is `[0x60214f0,0x60215bc)`, ELF virtual addresses, 204 bytes, mapped to file offsets `[100795632,100795836)`. Its SHA-256 is `a569fba870c7340f340fa5da011a7ad5eaf13e1f1daaceb8ddcde875b0761352`. Aligned decoding starts at the FDE entry and covers the entire range; 67 decoded instructions include padding.

The entry preserves the input selector from `esi` and object pointer from `rdi`. A vtable entry at offset 0x38 is compared with an unresolved pointer at 0x64eda08. The alternate path calls the loaded pointer, then rejoins the byte test. A nonzero byte at object+0x2c exits. The primary path loads a 32-bit value from object+0x28 into `edi`, bounds the selector to unsigned 0..4, and uses signed 32-bit offsets relative to table base 0x974298. Selectors outside that range return without this function issuing the file-advice call. The earlier virtual call can still have effects; this is not a no-side-effects claim.

All five table destinations are inside the selected FDE. Their legs set `ecx` to the matching selector value 0..4, clear `esi` and `edx`, restore the stack, then tail-jump to 0x601ed40. The thunk is an independently checked 9-byte ENDBR64/direct-jump sequence leading to PLT 0x63f1680. Its RIP-relative indirect jump uses slot 0x64ee790. Parsing `.rela.plt` and its linked symbol/string tables establishes one `R_X86_64_JUMP_SLOT` relocation at that slot naming `posix_fadvise`, addend 0. Thus the observed SysV argument tuple is `(object field at +0x28, 0, 0, selector)` for these legs; interpreting that field as an fd follows the imported ABI, not recovered source types.

There is no local instruction after the tail transfers to inspect or translate the imported return. No success/error behavior at higher callers is established. Early-return register contents are not assigned a recovered source-level meaning. Standard-library-looking objdump labels are nearest surviving symbols, NOT function names or source attribution.

## Implementation and comparison

`verify.py` and the test file are independently authored offline evidence tooling. No inferred can1357 source was read or copied. Imported artifact rights are unchanged; this packet contains bounded analytical disassembly, not a transplanted implementation or runnable node.

Authentication precedes structural verification. Corruption controls deliberately call the separate structural layer so target digest rejection cannot mask missing structural checks. They alter actual target bytes in memory: advice immediate, entry opcode, jump-table offset, thunk displacement, PLT displacement, relocation type, and ELF machine. The body-hash check detects the first two controls; it is not an independent behavioral model. Relocation, table and transfer checks operate on the corresponding mutated bytes. Positive proof uses the real pinned artifact and real binutils, not mocked decoding.

No Rust replacement, two-build comparison, runtime oracle or normalization mask is implemented or measured. Five advice legs over five selected table entries are validated, not five over all callers. Exploratory byte scanning found additional raw opcode candidates; these are NOT aligned-decoded or reported as a complete caller census. Public literal fadvise overlap queries returned no matching open/merged PR in saved selection evidence; integrated token/address grep returned no matches. Neither proves permanent exclusivity.

## Results and limitations

Eight scoped tests pass: one authenticated full-range proof plus seven byte-corruption controls. Required independent repository checks have not yet been run for this packet. Passing scoped tests alone is not approval or target equivalence. No progress catalogue or component gate is changed; all broader prerequisites remain unmet.

Next question: identify a real higher-level storage caller and determine how, if at all, its returned advice status is used. That work is outside this packet.
