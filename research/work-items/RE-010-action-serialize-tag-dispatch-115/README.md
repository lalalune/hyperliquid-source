# RE-010: reconstruct the node #115 `Action` serializer tag dispatch (92 variants, 6 copies)

With this packet, the whole first-word to variant dispatch of the node #115 `Action` enum can be rebuilt as code: the niche layout (first word `0x86 + index`, any word below `0x86` selects the dataful `VoteGlobal` variant), the declaration order of all 92 variants, the serde wire name of each one (`rename_all = "camelCase"` plus 17 `<Variant>Action` renames and 6 free renames), the three unit-struct variants and the payload hand-off. An executable reconstruction in `tools/action_tag_serialize_115.py` matches the byte evaluation of six unowned compiled copies for 1,362 of 1,362 tag words. All 136 spec and byte mutants are detected, and the arms plus the prologue explain 61,890 of 61,890 bytes of the six FDE extents.

- **Component ID:** `action-dispatch` (RE-010, Exchange handlers; `l1/exchange/impl_execute_action.rs` and handler splits are the reference area).
- **Target release and full SHA-256:** Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The tool refuses any other digest.
- **Source commit / reference commit:** repository main `05bc2de303c05525b71e7e257426e741bc66a390`. No reference source was copied. #94 material was not used.
- **Claim status:**
  - Observations: function extents, prologue constants, table entries, per-arm string slices, payload offsets and callee addresses, all read from ELF bytes.
  - Inferences: that these are monomorphized `impl Serialize for Action` bodies with `#[serde(tag = "type")]`; the Rust variant names (taken from the second string slice of each arm); the serde attribute form of the renames.
  - Unresolved: the payload types, what each per-variant serializer writes, and which serializer backend each copy belongs to.
- **Scope included and excluded:**
  - Included: six whole functions (FDE starts `0x2bce570`, `0x36aef70`, `0x36b3f80`, `0x4d84400`, `0x4d86d80`, `0x4d89700`), every table entry, every arm and every byte of each extent.
  - Excluded: five further copies with the same shape, because earlier merged packets already cite them as name formatters for selected arms. This packet does not decode or claim them. Also excluded: the per-variant serializer callees (only their addresses are recorded), the deserializer, and the handler execution (`execute_action`) path.
  - No node or visor code is executed.

## Reproduce

From the repository root, with Python 3 standard library only (no binutils, no subprocess):

```
python3 tools/action_tag_serialize_115.py --out research/work-items/RE-010-action-serialize-tag-dispatch-115
python3 -m unittest tests.test_action_tag_serialize_115
sha256sum -c research/work-items/RE-010-action-serialize-tag-dispatch-115/MANIFEST.sha256
```

The tool checks the input SHA-256 and parses sections with `tools/elf_index.py` (NOBITS sections excluded). It takes FDE extents from `tools/fde_extents.py`. It writes eight files and exits non-zero unless all of these hold: every case matches, the unmutated reconstruction matches before any mutant runs, every mutant is detected, and every byte of every extent is covered. Its output is deterministic: there are no timestamps, no absolute paths and no unordered iteration. It runs in about 6 s.

## Evidence

Coordinates are virtual addresses in node #115. The table address is the RIP-relative target of the prologue `lea`. Each entry is a signed 32-bit offset from the table base.

The two prologue forms are matched as fixed byte strings with four-byte immediates:

| Form | Copies | Bytes | Meaning |
| --- | --- | --- | --- |
| A | `0x2bce570`, `0x36b3f80`, `0x4d84400`, `0x4d86d80` | `53 48 83 ec 50 48 8b 06 48 2d <base> b9 <default> 48 0f 43 c8 48 89 fb 48 8d 05 <table> 48 63 0c 88 48 01 c1 ff e1` | out pointer `rdi` (kept in `rbx`), enum `rsi`, serializer `rdx`; `index = word - base` if `word >= base` (unsigned, `cmovae`) else `default` |
| B | `0x36aef70`, `0x4d89700` | `48 83 ec 48 48 8b 07 48 2d <base> b9 <default> 48 0f 43 c8 48 8d 05 <table> 48 63 0c 88 48 01 c1 ff e1` | enum `rdi`, serializer `rsi`; value returned directly |

In all six copies `base = 0x86` and `default = 20`. Table entries 0 to 91 hit exactly the 92 arm starts found by a linear sweep of the body (each arm ends in `ret` or an unconditional `jmp`). The mapping is a bijection. Entry 92 points to a non-arm address (`first_non_arm_entry_target` in `functions.tsv`), which is where the table ends. The compiled code has no upper bound check: words `>= 0x86 + 92` are invalid enum values, and `cases.tsv` records them as `outside-table` on both sides.

Each arm stores four `(pointer, length)` string slices in a stack array: enum name `Action`, Rust variant name, tag key `type`, wire name. After them it stores the serializer handle. Then it either:

- passes a payload pointer (`self+8` after the tag word, or `self+0` for `VoteGlobal` and `ReassessFees`), or loads payload words inline; or
- passes a unit-struct name (`NoopAction`, `ClaimRewardsAction`, `AgentEnableDexAbstractionAction`) to a shared helper.

It makes exactly one call. A human-readable excerpt (objdump, not used by the tool) of copy `0x4d86d80`, prologue and arm 3 (`cancel`), looks like this:

```
4d86d85: mov rax,[rsi] ; sub rax,0x86 ; mov ecx,0x14 ; cmovae rcx,rax ; mov rbx,rdi
4d86d9a: lea rax,[rip+...] # 914994 ; movsxd rcx,[rax+rcx*4] ; add rcx,rax ; jmp rcx
4d881d9: add rsi,0x8 ; lea rax,"Action" ; mov [rsp+0x8],rax ; mov qword [rsp+0x10],0x6
         ... "Cancel"/6 at +0x18, "type"/4 at +0x28, "cancel"/6 at +0x38, rdx at +0x48
         lea rdx,[rsp+0x8] ; mov rdi,rbx ; call 51a4b40 ; mov rax,rbx ; add rsp,0x50 ; pop rbx ; ret
```

The arm evaluator accepts only a whitelist of byte patterns: REX.W `89`/`8b`/`8d` with stack, RIP, `rsi`/`rdi`+disp8 or register operands; `c7` stack immediates; `add rsi/rdi,imm8`; `mov ecx/edx,imm32`; narrow payload loads; `call`/`jmp`/`ret`/`pop rbx`/`add rsp`. Any other byte fails closed. The files are:

- `functions.tsv`: extent, form, constants, table, arm count, first non-arm entry and body SHA-256 per copy.
- `arms.tsv`: 552 rows, one per copy and index. Each row gives the arm start, the four strings, the payload form, the unit name, the per-variant serializer call and the number of evaluated instructions.
- `insns.tsv`: every decoded instruction (VA, length, raw bytes, decoded effect, indices of the arms that run it) of one copy per distinct class of prologue form and payload shapes: `0x2bce570` (A, inlined `SpotUser`), `0x36aef70` (B), `0x36b3f80` (A, inlined `ValidatorL1Stream`) and `0x4d84400` (A). Each listed copy's rows add up to its whole extent. `0x4d86d80` and `0x4d89700` have the same arm results as `0x4d84400` and `0x36aef70`. They are decoded and coverage-checked the same way, but not listed.
- `variants.tsv`: the reconstructed enum (index, Rust name, wire name, naming rule, tag word, payload, unit struct, payload forms across copies, variants sharing a serializer callee).
- `action_enum.rs.txt`: the reconstruction written as a Rust declaration with serde attributes, generated from the checked spec.

## Implementation and comparison

The reconstruction is `spec_serialize` in the tool, a pure function `(spec, tag_word, copy) -> (index, enum, rust_variant, tag_key, wire_name, payload, unit_struct)`. It is written independently of the decoder: the variant order is a literal tuple, and wire names come from a rule (camelCase, else `<Variant>Action` for the `SUFFIX_ACTION` set, else an explicit `RENAMES` entry). It also holds the unit-struct set, the two `self+0` payload variants and two copy-specific inlined payloads:

- `SpotUser` in `0x2bce570` loads one u32 at `self+8`.
- `ValidatorL1Stream` in `0x36b3f80` loads the words at `self+16` and `self+24`, the pointer and length of a three-word buffer.

The byte side is `byte_serialize`. It applies the decoded `sub`/`cmovae` arithmetic to the tag word, reads the table, and evaluates the selected arm.

- Cases: for each copy, every tag word below the niche base (134), every niche value (92) and the first value past the table (1). In total 6 x 227 = 1,362 cases, 1,362 matched (`cases.tsv`).
- Coverage: in each copy, the prologue and the union of instructions evaluated across all arms equal the FDE extent byte for byte (`covered_bytes == bytes`).
- Negative controls (`mutants.tsv`), all detected:
  - 130 spec mutants: niche base +-1, the wrong dataful variant, the wrong tag key or enum name, each suffix rename dropped (17), each free rename dropped (6), each unit variant dropped (3), each `self+0` payload dropped (2), each inlined payload dropped and one spurious inlining added, every adjacent variant swap (91), the last variant dropped, and a spurious suffix added.
  - 6 byte mutants on copy `0x2bce570`: swapped table entries, sub immediate +1, default index +1, a corrupted first arm opcode, an `int3` at the extent end, and a wire-name length -1. The opcode and `int3` mutants fail closed; the others are caught as case mismatches.
- No Rust build is included: the declaration in `action_enum.rs.txt` is a reconstruction record, not compiled code (Rust path, Cargo and build comparison: not yet implemented).

## Results and limitations

| Metric | Value |
| --- | --- |
| Copies decoded | 6 (2 prologue forms) |
| Arms per copy / table entries | 92 / 92, bijective |
| Bytes covered | 61,890 / 61,890 |
| Cases matched | 1,362 / 1,362 |
| Mutants detected | 136 / 136 (130 spec, 6 byte) |
| Naming rules | 69 camelCase, 17 `<Variant>Action`, 6 free renames |

Variants that share a per-variant serializer callee in at least one copy (inferred to have the same payload type; unverified):

- `UsdSend` and `Withdraw3`
- `RegisterReferrer` and `SetReferrer`
- `CWithdraw` and `CDeposit`
- `UserDexAbstraction` and `UserPortfolioMargin`

The three unit variants share the unit-name helper.

Limits:

- The payload types and the content written by the 92 per-variant serializers are not decoded.
- The serializer backend of each copy is not identified. The two forms differ in ABI, but the backend is not named.
- `ReassessFees` passing `self+0` is observed, but its payload layout is unresolved.
- The Rust variant names are the compiled string literals; whether they equal the original identifiers is an inference.
- This packet requests no gate change: `action-dispatch` remains 0/4.

Next question: decode the deserializer side of the same enum, from the `type` string visitor to the variant index. Show that it is the inverse of this map, including the `Action`-suffixed and free renames and any aliases. Then follow one shared serializer callee (`UsdSend`/`Withdraw3`) to prove the shared payload type.
