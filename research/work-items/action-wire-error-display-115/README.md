# action-wire: reconstruct the node #115 action-error Display function (418 tags, 337 static texts, 81 templates)

This packet makes the user-facing action error table of node #115 reconstructible as an executable
function: for every u16 error tag 0..417 it recovers whether the arm writes one static string or
calls the node's template interpreter, the exact message text or template, the number and source of
every template argument, and the formatter function of each argument. An independent Rust port can
now reproduce the full `Display` of this error type (for example tag 93 `Nonce already used.`,
tag 96 `Nonce mismatch.`, tags 203/204/205 `Invalid nonce: nonce too low {} < {}` /
`nonce too high {} > {}` / `duplicate nonce {}`, tag 208 `Action already expired`, tags 138-143 the
`SignedAction` length and flag-byte errors, tag 147 `Mainnet and testnet require different
signature.`) and can fix two facts the strings alone do not give: the dispatch has no range check
(tags above 417 index past the table), and the message template language has a long-literal form
(`0x80` + u16 length) that only tag 82 uses.

- Component ID: `action-wire` (task: recover tags, signing domains, replay checks and error precedence;
  this packet recovers the error tags and messages of the replay, signature and expiry checks).
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No
  reference source was used; every text comes from the binary's own bytes.
- Claim status:
  - Observation: the body extent, the jump table, every arm's instructions, the texts, templates,
    argument stores and formatter addresses, and the equality of the model with the emulated
    machine code in all cases.
  - Inference: that tags are the discriminants of one error enum, the template grammar names
    (`0xc0` = argument, `0x80` = long literal), and that the call target is a message formatter.
  - Unresolved: the Rust type name of the enum, the bodies of the 26 formatter functions, the body
    of the template interpreter `0x1680500`, and which checks raise which tag (error precedence).
- Scope included: the single FDE `0x46ef710..0x46f312f` (14,879 bytes, 3,478 instructions), the
  418-entry rel32 table at `0x7d8c1c`, all arms, the template byte strings they reference, the
  GOT slot `0x64df6f0` and its RELATIVE relocation.
- Scope excluded: what the 19 reference sites do with the slot (they are listed, not analysed), the formatter functions,
  the interpreter, and the raise sites. `RE-001-node115-staking-error-display` and
  `RE-010-builder-approval-115` select a few arms of this same body by text; this packet
  reconstructs all of it. No progress gate is requested.

## Reproduce

From the repository root, with Python 3 and no other program:

```
python3 tools/action_wire_error_display_115.py --out research/work-items/action-wire-error-display-115
python3 -m unittest tests.test_action_wire_error_display_115
```

The producer refuses any input whose SHA-256 is not the #115 digest, finds the body through its
`.eh_frame` FDE with the shared `tools/fde_extents.py`, reads sections through `tools/elf_index.py`
(NOBITS excluded) and RELATIVE relocations from `.rela.dyn`. It never runs the binary and calls no
external program. A run takes about 20 s and 260 MB. All output is deterministic.

Human-readable excerpt (GNU objdump, not used by the tool): a static arm and the head of the body.

```
46ef710: sub rsp,0x38 ; movzx eax,WORD PTR [rdi] ; lea rcx,[rip+..] # 0x7d8c1c
         movsxd rax,DWORD PTR [rcx+rax*4] ; add rax,rcx ; jmp rax      # no range compare
static:  mov rdi,[rsi] ; mov rax,[rsi+8] ; mov rax,[rax+0x18] ; lea rsi,[rip+..] ; mov edx,len
         add rsp,0x38 ; jmp rax                                      # write_str(text)
template: ... mov [rsp+0x10],ptr ; mov [rsp+0x18],formatter ; mov rdi,[rsi] ; mov rsi,[rsi+8]
         lea rdx,[rip+template] ; lea rcx,[rsp+0x10] ; call [0x64df6f0] ; add rsp,0x38 ; ret
```

## Evidence

Coordinates are virtual addresses in the #115 image.

| File | Rows | Content |
| --- | ---: | --- |
| `arms.tsv` | 418 | per tag: arm VA, kind (`str`/`tmpl`), argument count, instruction count, text or template VA, length, rendered text with `{}` holes |
| `entry-references.tsv` | 19 | every RIP-relative reference to the GOT slot `0x64e28a0` (whose RELATIVE addend is the body) found by byte pattern, with the containing FDE start (13 distinct functions) |
| `template-pieces.tsv` | 226 | per template: every literal / argument piece in order |
| `template-args.tsv` | 97 | per argument: formatter function VA and where the value comes from (`p` payload pointer, `sp` stack slot holding a payload pointer, `sc` stack copy of 8 payload bytes, `si` stack immediate, `va` static data) |
| `formatters.tsv` | 26 | distinct formatter functions and use counts |
| `shared-arms.tsv` | 0 | arms reached by more than one tag (none: all 418 are distinct) |
| `negative-controls.tsv` | 46 | each wrong model, corrupted byte or out-of-range input with the number of cases that catch it |
| `summary.json`, `measure.json` | - | counts and the machine-readable case / control totals |

Byte observations:

- The body starts `sub rsp,0x38; movzx eax,[rdi]` and indexes 418 rel32 slots at `0x7d8c1c`; every
  target lies inside the FDE and all 418 targets are distinct arm starts. There is no compare, so an
  out-of-range tag is not an error path of this body.
- 337 arms are static: the text pointer and length are RIP-relative `lea` and `mov edx`, written
  through the vtable slot at offset `0x18` of the formatter.
- 81 arms are templates (tag 201, `{} asset={}`, ends by a `jmp rel32` at `0x46f13a4` into the shared tail `0x46f2ae3`). They store `(value
  pointer, formatter)` pairs at `[rsp+0x10+16k]` and call the same target `0x1680500` (through
  the relocated GOT slot `0x64df6f0`). Argument values: 79 are pointers to a stack slot that holds a
  payload pointer, 9 point at static data, 5 are 8-byte copies of payload words (one with `movups`),
  4 are stack immediates, e.g. tag 159 `Can only manually unjail once every {} seconds` stores
  `0x4072c00000000000` (300.0 as f64, inferred).
- The template language, read from all 81 templates and confirmed because every template then parses
  with exactly as many holes as the arm stores arguments and only printable text: byte `0` ends,
  `1..0x7f` introduces that many literal bytes, `0xc0` is the next argument, `0x80` introduces a
  literal with a u16 length (used once, tag 82, a 166-byte literal).

## Implementation and comparison

`tools/action_wire_error_display_115.py` contains two independent executions of the same bytes:

1. A concrete x86-64 subset emulator (`Machine`) with a fixed decoder (a fixed subset of mov/lea/add/sub/movups/movabs/movzx/movsxd/jmp/call/ret forms; any
   other byte is rejected). The error value is a 512-byte payload whose first two bytes are the tag;
   the formatter is a fake object whose vtable slot `0x18` is a sentinel; stores outside the stack
   are rejected. Its observable result is `('S', text pointer, length, out)` or
   `('T', callee, template VA, ((formatter, argument), ...), out, vtable)`.
2. A symbolic model (`sym_arm`, `arm_row`) that follows each arm with tagged values instead of
   numbers and yields rows `S(text VA, length)` / `T(template VA, ((formatter, source), ...))`.
   `model_expect` turns a row and a payload into the same observable tuple.

`display_segments` / `display_text` expose the reconstruction as a function (static text or ordered
`text` / `arg(formatter, source)` segments; tags above 417 raise `IndexError`), and the tests check
that it reproduces every row of `arms.tsv`. `entry_references` scans `.text` for
`[REX] 8b|8d|ff|89 ModRM(rip) disp32` that resolve to the GOT slot and finds 19 sites, the same count
that `RE-001-node115-staking-error-display` reported; instruction boundaries are not proven.

`check` runs every tag with 30 payload variants (some carrying payload-relative words) = 12,540
cases and compares the two results. The template grammar is checked separately
(`grammar_violations`): hole count, no parse error, printable literals.

## Results and limitations

- 12,540 cases, 0 mismatches (418 tags x 30 payloads).
- 46 negative controls, 46 detected: 22 wrong models (swapped or shifted texts, off-by-one lengths,
  wrong formatter, wrong source offset or kind, swapped / dropped / added arguments, shifted or wrapped
  tags, aliased last slot), 17 corrupted code or table bytes (table slots, text `lea`/length, vtable
  offset, prologue load, template `lea`, argument array base, call slot, `movups`/`movabs`/`add rdi`
  operands, prologue table `lea` and scale, the call's relocation addend), 3 wrong template grammars,
  3 tags outside the table and a wrong digest.
- The emulator is a self-written subset interpreter; agreement of two models of the same bytes is
  not proof that the Rust compiler's intent is recovered, and the formatter bodies are not run.
- Unresolved: formatter semantics (26 functions), the interpreter `0x1680500`, the raise sites for each
  tag (error precedence), the enum's Rust name, and whether tags above 417 are reachable.
- Next question: bind the raise sites of the nonce tags 203/204/205 and 93/96/97 to the nonce-set
  checks in `l1/src/nonce_set.rs` and recover their order against signature and expiry checks.
