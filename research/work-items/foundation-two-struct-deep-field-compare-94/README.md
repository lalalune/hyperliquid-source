# foundation-two-struct-deep-field-compare-94: what does the 24-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 24-byte FDE window, its 8 int3 padding bytes, the two-struct deep-field compare rule, the one confirmed caller, the no-naming-relocation scan, and the one-direct-caller scan.
- Excluded: the meaning of the struct fields, the meaning of the compared values, the caller's behavior beyond the call itself, other comparators, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: seven instructions, no calls inside, no branches, and a rule fully determined by two two-hop loads and one unsigned compare. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x51c0c00`, no open pull request title mentions it or two-struct-deep-field-compare, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_two_struct_deep_field_compare.py --check research/work-items/foundation-two-struct-deep-field-compare-94/evidence.json
python3 -m unittest tests.test_foundation_two_struct_deep_field_compare -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x51c0c00 --stop-address=0x51c0c20 artifacts/node/94/hl-node
objdump -d --start-address=0x51e6a70 --stop-address=0x51e781a artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

## Observations

### Window identity

- FDE `[0x51c0c00, 0x51c0c18)`, 24 bytes, `.eh_frame+0x29ff20`, CIE at offset 0, `zR` pcrel sdata4, confirmed with GNU `--dwarf=frames`. The next FDE starts exactly at `0x51c0c20` (`[0x51c0c20, 0x51c0c25)`), so the 8 int3 bytes between the body end and the next FDE start are padding, not body. The checker locks the body and the padding separately.
- Body SHA-256: `ba01a0bc0b332ab68baefbed1a8d6882f4170d1f086235c4b08339f2bc0ae0fd`.
- Retained disassembly (`window.objdump.txt`):

```text
51c0c00: endbr64
51c0c04: mov 0x8(%rdi),%rax
51c0c08: mov 0x8(%rsi),%rdx
51c0c0c: mov 0x78(%rax),%rax
51c0c10: cmp %rax,0x78(%rdx)
51c0c14: setb %al
51c0c17: ret
```

### Decoded rule

- `rax = [rdi+8]`, then `rax = [rax+0x78]` (the first struct's deep field).
- `rdx = [rsi+8]`, then the compare reads `[rdx+0x78]` (the second struct's deep field).
- `cmp %rax,0x78(%rdx)` computes `[rdx+0x78] - rax` and `setb %al` yields 1 exactly when the second deep field is strictly below the first, unsigned.
- Return rule: `%al = 1` iff `[[rsi+8]+0x78] < [[rdi+8]+0x78]` as unsigned qwords, else 0. No field is written. No branch, no call inside the window.
- Edge behavior is fully determined by the compare: equal fields give 0, and the unsigned reading (not signed) decides the `0x8000000000000000` vs `0x7fffffffffffffff` case (1).

### Call and data edges

- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` site landing on the window start: `0x51e7377` (bytes `e8 84 98 fd ff`), confirmed as an instruction start by linear disassembly from its caller FDE start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan.
- Caller FDE: `[0x51e6a70, 0x51e781a)`, retained in full in `caller.objdump.txt`. Setup immediately before the call: `add %rbx,%rcx; add %rbx,%rdi` (preceded by `mov %rax,%r8; mov %r8,%rdi; mov %r10,%rsi; shl $0x4,%rcx; shl $0x4,%rdi`). The caller's purpose is not claimed; the caller tests `%al` right after the call (`test %al,%al; jne 0x51e7340`), which is consistent with the byte result but is caller behavior, not window behavior.
- Relocations: no record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries).
- Nearest claimed window: binary search over 16-byte entries `0x51cb570` (packet #76), `0xa970` away.

## Inferences

- The "two-struct deep-field compare" label is an inference from the instruction shape: two two-hop loads feeding one unsigned compare. It is kept separate from the observed rule above.
- The compared qwords are presumably a shared field of two instances of one struct type, but the bytes do not identify the type, so no such claim is made.

## Distinction from packet #65

Packet #65 (`0x5361710`, two-hop field select) loads from a single two-hop base and *selects* between two fields (`p=[rdi+8]`, `q=[p+0x1e0]`, `q` nonzero then `[q+8]` else `[p+0x178]`). This window loads the same deep offset from *two* two-hop bases and *compares* them, returning a byte. Selection vs comparison, one base vs two bases: the mechanisms differ even though both windows hop twice. No shared primitive is claimed, and no census of comparators or selectors was built.

## Unknowns

- The struct types, the meaning of the `+0x8` hop and the `+0x78` field, and the caller's purpose.
- Whether indirect callers or tail jumps reach this window (outside the byte-pattern scan's scope).
- Whether the result byte is consumed as a boolean or as one byte of a wider value (only `%al` is written by `setb`; the upper bytes of `rax` are the high bytes of the loaded first deep field, and no zero-extended boolean is claimed).

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
