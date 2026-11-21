# Node #115 action-wire variant dispatch inventory

This packet records the raw dispatch table and the immediate per-arm call shape for an adjacent action-wire variant dispatcher. It extends the existing `action-dispatch` packet's bounded work from the separate classifier at `0x36c30f0`; it does not relabel these arms as source enum variants or claim runtime semantics.

- Component: `action-wire`
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Question: Which relative table target does each numeric tag index select at `0x36c3180`, and which targets contain an immediate RIP-relative indirect call through a statically relocated slot?
- Coordinates: linked ELF virtual addresses; table entries are signed little-endian 32-bit offsets relative to table VA `0x79b120`.
- Inputs: captured target artifact only; no reference source text used.

## Reproduce

```sh
python3 tools/action_wire_variant_methods_115.py --out /tmp/action-wire-variant-methods-115
python3 -m unittest tests.test_action_wire_variant_methods_115
```

The script checks the full target digest, reads only mapped `.text` and `.rodata`, parses `.rela.dyn` directly, and refuses table targets outside the recorded FDE extent. It does not execute the captured binary. `arms.tsv` gives all 92 indices (`0x86..0xe1`), target addresses, observed 12-byte prefixes and, where found, exact call site, GOT slot and `R_X86_64_RELATIVE` addend.

## Evidence

The dispatcher bytes at `0x36c3180` perform `tag - 0x86`, select index `0x14` when the unsigned comparison is below the base, load a signed table-relative target from `0x79b120`, add the table base, and jump through it. The indexed table has 92 unique targets within the `.eh_frame` FDE extent `0x36c3180..0x36c5348` (8,648 bytes). The next-index FDE inventory independently records that extent; an FDE is an unwind range, not proof of a source function boundary.

Across the 92 target prefixes, 20 contain a RIP-relative indirect call whose slot has an `R_X86_64_RELATIVE` relocation; 72 begin with `mov byte ptr [rsp+disp32], 0`. The call slots resolve to 20 static addends recorded in `arms.tsv`. These are byte-level dispatch and relocation observations. They do not establish that every numeric tag is accepted, identify source-level names, explain the called methods, or prove the full semantics of any arm.

## Limits and next step

The next bounded step is to trace one slot target together with its call arguments and relevant downstream body, starting with tag index `0xd1` / slot `0x64e8e48` / addend `0x442d000`. Do not infer action names from the numeric indices. This packet advances no full-scope component gate and does not claim equivalence.
