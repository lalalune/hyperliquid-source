# RE-010: reconstruct the fourth sibling's variant matchers (visit_str + visit_bytes) and name the 79-variant node-environment enum

This packet reconstructs, as one executable pure function checked against the original bytes, the
`visit_str` and `visit_bytes` variant matchers that the fourth 1769-byte copy of the node #115
MessagePack identifier decoder calls. The other three copies (PERP, SHORT114, TAG18) and the
`Action` anchor copy are reconstructed elsewhere; that work explicitly left this fourth copy
0x14b3080 undecoded. A reconstruction can now decode one more serde enum name-for-name: the
79-name node-environment enum (`Ec` .. `EbHlPerp`) whose index-based form is the N1 number
dispatcher 0x14b7dc0. This settles the number-identifier packet's next question, which asked
which enum the N1 dispatcher serves and pointed at this decoder's `visit_str` matcher as the
place that would name the variants.

- Component ID: `action-dispatch` (task RE-010)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: lalalune/hyperliquid-source main `a8616af9432b8d8517b2af677880e117b7c28ef3`;
  no reference source was used
- Claim status: observation (byte-level outcomes of the two matchers on every listed input, the
  decoder bindings, the VARIANTS slice and the success-store immediates), inference (that these
  are serde-derived `__FieldVisitor` methods of one enum, and that the enum is the node's
  environment selector), unresolved (the Rust type name of the enum, the serializer side, and the
  callers of the decoder copy)
- Scope included and excluded: included are the two matchers 0x14bf120 (visit_bytes) and
  0x14c12b0 (visit_str), their whole FDE extents (1,982 instructions), their VARIANTS slice, the
  visit_bytes landing pad, and the call offsets that bind them to the decoder copy 0x14b3080
  (including its +162 GOT dispatch to the already-reconstructed N1 dispatcher). Excluded are the
  body of the decoder copy, the number dispatcher it reaches through the GOT slot, the callers of
  the decoder, and the local error constructor 0x14a1970, `String::from_utf8_lossy` and the
  allocator free, which are contract stubs whose arguments are checked. No progress gate is
  requested.

## Reproduce

From the repository root (Python 3 standard library only, no binutils, the binary is never run):

```
python3 tools/re010_env79_variant_matchers_115.py --out research/work-items/RE-010-env79-variant-matchers-115
python3 -m unittest tests.test_re010_env79_variant_matchers_115
```

The tool checks the input SHA-256 first and fails on any other input. It reads `.rela.dyn`,
`.rela.plt`, `.dynsym`/`.dynstr`, `.eh_frame` (through `tools/fde_extents.py`), the LSDA call-site
table and the matcher bytes with `struct`, and rewrites all eleven generated files. It takes about
40 s. Two regenerations into different folders were byte-identical (`diff -r` empty). The unit
test regenerates the folder into a temporary directory and compares every file byte for byte.

## Evidence

Coordinates are virtual addresses in the #115 image. File offsets are derived from the section
headers; NOBITS sections are never read.

### Decoder copy to matcher binding (`decoder-bindings.tsv`)

Every 1769-byte decoder copy calls its `visit_bytes` matcher at offsets +1057 and +1195 and its
`visit_str` matcher at +1238 (`e8 rel32`), and reaches its number dispatcher through the GOT slot
0x64dff80 at offset +162. The `Action` anchor and the three sibling copies check unchanged; the
fourth copy binds as:

| enum label | decoder | visit_bytes (+1057, +1195) | visit_str (+1238) | visit_u64 via GOT (+162) | VARIANTS slice | names |
| --- | --- | --- | --- | --- | --- | --- |
| ENV79 | 0x14b3080 | 0x14bf120 (5,788 B) | 0x14c12b0 (2,556 B) | 0x14b7dc0 (N1) | 0x63f8788 | 79 |

The label is this packet's name, not a Rust identifier.

### VARIANTS slice

Each matcher's error tail contains a `lea rcx,[rip+slice]` followed within three instructions by
`mov r8d,79`, the `(expected, len)` pair passed to the error constructor. Every 16-byte slot of
the slice at 0x63f8788 carries an `R_X86_64_RELATIVE` relocation to the name bytes, and the second
word is the length. The names are in `summary.json` and `names.tsv`:

`Ec DummyTokyo DummyTokyo2 GaOnchain GbOnchain NodeTestnet NodeTestnet2 NodeTestnet3
NodeTestnet4 Ea Ea2 Ea3 EaMm EaTx HeavyTestnet HeavyMainnet Eb Ed Ee SoloTestnet SoloMainnet
LockerTestnet LockerMainnet RpcTestnet RpcSandbox RpcMainnet RpcMainnet2 Sa Sb Sc Sd WebSandbox
SoloSandbox NvTestnet NvTestnet2 NvMainnet NvMainnet2 NvMainnet3 JoinMainnet DummyNv FBinSpot
FBinSpot2 FBinSpot3 FBinSpot4 FBinSpot5 FBinSpot6 FBinSpot7 FBinSpot8 FBinPerp FBinPerp2
FOkexSpot FOkexSpot2 FOkexPerp FHuobiSpot FHuobiSpot2 FHuobiSpot3 FHuobiSpot4 FHuobiPi FHuobiPerp
FCobSpot FKraSpot FBybitSpot ScratchDummy ScratchCron OBinSpot FHlPerp GaHlPerp GaHlPerp2
GaHlPerp3 GbHlPerp GbHlPerp2 GbHlPerp3 GcHlPerp GcHlPerp2 GdHlPerp GdHlPerp2 GsHlPerp EaHlPerp
EbHlPerp`

Name lengths: 2 bytes x9, 3 x2, 4 x2, 7 x2, 8 x13, 9 x20, 10 x12, 11 x11, 12 x6, 13 x2.

### Success stores (`names.tsv`)

Every accepted name ends in exactly one `movw $imm16` store through the out pointer with
`imm16 = (variant << 8) | 0x09`. The tag byte 9 is the `Ok` niche of the 32-byte result also used
by the sibling matchers. Here every store immediate equals the name's slice position: the 79
names are 79 distinct variants and there are **no serde aliases** (the PERP enum of the sibling
packet has one; this enum has none). As an independent cross-check, `NvTestnet` is variant 33
here, matching the discriminant 33 that the RE-015 static-config packet observed for `NvTestnet`
in the config code that consumes this enum.

### Dispatch shape (`jump-tables.tsv`, `insns.tsv`)

The two matchers do not share a code shape:

- visit_str: a 12-entry length switch (`lea rcx,[rdx-2]; cmp rcx,11; ja`, table 0x4643a0) for
  lengths 2..13. Short names are compared with `cmpw`/`cmpl` immediate chains; names of 9..13
  bytes through `movabs` + `xor` + `or` reductions over the input qword and tail bytes. Each
  accepted name jumps to a shared leaf block holding its success store.
- visit_bytes: a 12-entry length switch (table 0x4641c0) plus nine further tables (4..20
  entries) that split the longer length classes by leading bytes before the same immediate and
  SWAR compares. It is 5,788 bytes against visit_str's 2,556 for this reason.

Human-readable excerpt (objdump, not used by the tool), visit_str entry and one leaf:

```
14c12b0: mov    %rdi,%rax                 ; out pointer held in rax
14c12b3: lea    -0x2(%rdx),%rcx
14c12b7: cmp    $0xb,%rcx
14c12bb: ja     14c1ad8                   ; length outside 2..13 -> error tail
14c12c1: lea    0x4643a0,%rdi             ; length jump table
14c12c8: movslq (%rdi,%rcx,4),%rcx
14c12cf: jmp    *%rcx
14c1334: movw   $0x1e09,(%rax)            ; `Sd` -> variant 30
14c1b1a: movw   $0x0009,(%rax)            ; `Ec` -> variant 0
```

### Error tails and landing pad (`lsda-call-sites.tsv`, `unwind-cases.tsv`)

The visit_str matcher has no LSDA. On a miss it calls the local error constructor 0x14a1970 with
`out` pointing at a 32-byte stack temporary, `value=(rsi,rdx)` and `expected=(rcx=0x63f8788,
r8=79)`, then copies the temporary to the real out pointer with two `movups`. The constructor is
132 bytes, the same size as serde's `unknown_variant` 0x17fbba0 used by the sibling copies, and
itself calls 0x14a9620 after staging the value, the expected slice and two static strings; it is
modelled as a stub whose arguments are checked, and its body is not decoded here.

The visit_bytes matcher has an LSDA with 3 call sites:

1. `String::from_utf8_lossy` through GOT slot 0x64df640 (RELATIVE -> 0x141ca00), no landing pad;
2. the error constructor 0x14a1970, with landing pad 0x14c079d;
3. the free of an owned Cow through GOT slot 0x64df4a0 (RELATIVE -> 0x635de30) when the string
   is owned, followed by `_Unwind_Resume` (the PLT stub 0x63f0a50, checked through its
   `.rela.plt` JUMP_SLOT symbol).

The landing pad frees the owned string iff the input was invalid UTF-8, then resumes.

## Implementation and comparison

The reconstruction is `variant_table` + `reconstructed_match` in the tool (pure Python), rendered
as Rust-like pseudocode in `matchers.rs.txt`:

```
match value {                       // exact, case-sensitive, whole slice
    b"<VARIANTS[p]>" => Ok(variant(p)),   // variant(p) = p (this enum has no aliases)
    _ => Err(unknown_variant(&String::from_utf8_lossy(value), &VARIANTS)) // Owned dropped
}
```

The original bytes are run by a fixed-pattern x86-64 subset interpreter in the tool (about 450
lines). It handles the integer subset these matchers use, including accumulator-immediate forms,
`setcc` and byte compares, plus the SSE move group (`movups` load/store) that the error tails
use. The interpreter models the input, output, heap and stack as bounded buffers. Any read past
the input, any store outside writable buffers, any unknown opcode and any unbalanced `ret` is a
fault, not a result. The error constructor, `from_utf8_lossy` and free are stubs that check
their arguments: VARIANTS pointer and count, the lossy text, and the owned-pointer/capacity
pair. They write a 32-byte marker error, or in unwind mode transfer to the landing pad that the
LSDA call-site table names.

Inputs (`cases.tsv`, built from the bytes): every name; each byte +1 / -1 / case-flipped; drop
first / last byte; `+s`, `+NUL`, doubled; high last byte; invalid, two-byte and truncated UTF-8
tails; all 256 one-byte strings; `a`*0..32 and `\xff`*0..32. The visit_str matcher runs the
valid-UTF-8 subset.

| function | cases | mismatches | instructions executed | unwind cases (mismatches) |
| --- | --- | --- | --- | --- |
| ENV79 visit_bytes 0x14bf120 | 2,934 | 0 | 1,404 / 1,404 | 212 (0) |
| ENV79 visit_str 0x14c12b0 | 2,559 | 0 | 578 / 578 | - |

The two functions total 5,493 normal runs and 212 unwind runs. On every valid-UTF-8 input,
visit_str and visit_bytes give the same result (`str_bytes_agree_on_utf8_cases` equals
`utf8_cases`, 2,559).

Negative controls:

- Model mutants (`mutants.tsv`): 28 / 28 rejected (the sibling packet's 16 general mutants at
  both entry points, minus the byte-only ones at visit_str). Among them: case-insensitive,
  prefix, sorted order, swapped indices, ignore last byte, first byte only, accept trailing NUL,
  strip whitespace, strict-UTF-8 text, never / always free, lossy-then-match and ASCII fold.
- Image mutants (`summary.json` `image_mutants`): 18 / 18 single-bit flips rejected. Each is the
  immediate low byte of a sampled `cmp`/`xor` or the variant byte of a sampled success store, in
  both functions.
- Unit tests: wrong digest, unmapped read, non-FDE start and a non-call byte at a binding offset
  are rejected. A one-bit store corruption turns `Sd` -> 30 into 31.

No Rust implementation is built in this packet: not yet implemented.

## Results and limitations

- 2 / 2 matchers reconstructed with 0 mismatches over 5,493 + 212 runs and 1,982 / 1,982
  instructions executed. 28 / 28 model and 18 / 18 image mutants were rejected. The enum has 79
  variants and 79 accepted names; there are no aliases.
- The names are node-environment names (testnet / mainnet / sandbox node roles and external-feed
  roles), and the RE-015 static-config packet already reads some of them as config values; the
  enum is inferred to be the node's environment type, but its Rust type name is not established.
  "ENV79" is a label.
- Why this decoder has a per-copy local error constructor (0x14a1970) where the sibling copies
  call serde's `unknown_variant` (0x17fbba0) directly is observed but not explained here; its
  body and its callee 0x14a9620 are outside this packet.
- The interpreter runs a subset; outcomes outside the listed inputs are inferred from full
  coverage and the compare structure, not executed.
- The callers of the decoder copy 0x14b3080, and which config value it deserializes, are not
  decoded here.

Next question: which serializer emits these 79 names, and which config field does the decoder
0x14b3080 serve? Together they would tie the enum to its Rust type. What is the local error
constructor 0x14a1970: a per-crate `unknown_variant` variant, or a different error type whose
formatter is 0x14a9620?
