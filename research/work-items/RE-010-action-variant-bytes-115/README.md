# RE-010: reconstruct the `Action` variant `visit_bytes` matchers of node #115

With this packet the byte-slice entry point of the `Action` variant identifier
visitor can be rebuilt and checked: all five node #115 copies (two result
forms) are reconstructed as one pure function `action_variant_from_bytes` that
maps the 92 wire names to variant indices 0..91 by exact, case-sensitive,
whole-slice comparison and otherwise reports `unknown_variant` with the
`String::from_utf8_lossy` text, freeing that text exactly when it was owned
(invalid UTF-8), on the normal path and on the unwind path. The reconstruction
agrees with an interpretation of the original bytes on 14,105 normal and 1,860
unwind runs with every instruction of every copy executed.

- Component ID: `action-dispatch` (task RE-010)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main `05bc2de303c05525b71e7e257426e741bc66a390`;
  `references/can1357-hl` was not used (the wire names come from the binary's VARIANTS slices).
- Claim status: observation for the byte behaviour (interpreted and compared);
  inference for the Rust-level names (`visit_bytes`, `from_utf8_lossy`, the error types); unresolved items are listed below.
- Scope included and excluded: included are the five same-family functions
  `0x2b99100`, `0x3659d20` (form A) and `0x2b9cdb0`, `0x365d9d0`, `0x4d63870`
  (form B), each over its whole FDE extent, their length switch, inner byte
  switches, success stores, error tail, LSDA call sites and landing pad.
  Excluded: the callees (`from_utf8_lossy` at `0x141ca00`, the free at
  `0x635de30`, the unknown_variant constructors) are modelled by checked stubs
  and not decoded; the `visit_str` siblings `0x2ba1af0` and `0x3662730` belong to
  the separate type-matcher packet and are not decoded here. Payload
  deserialisation after the variant is known is not covered.

## Reproduce

From the repository root, Python 3 standard library only, no binutils and no
execution of the node:

```
python3 tools/re010_action_variant_bytes_115.py --out research/work-items/RE-010-action-variant-bytes-115
python3 -m unittest tests.test_re010_action_variant_bytes_115
sha256sum -c research/work-items/RE-010-action-variant-bytes-115/MANIFEST.sha256
```

The tool checks the input SHA-256 first and fails on any other input. It reads
FDEs with `tools/fde_extents.py` (`eh_frame_records`, `uleb`) and sections with
`tools/elf_index.py`; NOBITS sections are excluded from VA reads. One run takes
about 21 s and the output is byte-identical between runs (checked with two
output folders and `diff -r`). The exit status is 1 if any mismatch, unexecuted
instruction, non-one-to-one success store or surviving mutant is found.

## Evidence

Coordinates are virtual addresses of the PIE image. They are not file offsets
(`.text` VA `0x1419300` is at file offset `0x1418300`); the tool maps every VA
to a file offset through the section headers.

Function extents (`copies.tsv`, from `.eh_frame`):

| copy | start | FDE end | bytes | form | instructions | VARIANTS slice | unknown_variant callee | LSDA |
|---|---|---|---|---|---|---|---|---|
| A1 | 0x2b99100 | 0x2b9cda4 | 15,524 | A | 3,385 | 0x644cc40 | 0x2cf1360 | 0x26a9bc |
| A2 | 0x3659d20 | 0x365d9c4 | 15,524 | A | 3,385 | 0x6467f98 | 0x45a8fe0 | 0x2b9960 |
| B1 | 0x2b9cdb0 | 0x2ba0a62 | 15,538 | B | 3,387 | 0x644cc40 | 0x17fbba0 | 0x26a9d0 |
| B2 | 0x365d9d0 | 0x3661682 | 15,538 | B | 3,387 | 0x6467f98 | 0x2f7fef0 | 0x2b9974 |
| B3 | 0x4d63870 | 0x4d67522 | 15,538 | B | 3,387 | 0x649bac8 | 0x47d2d80 | 0x375cd8 |

The linear sweep of each FDE extent decodes every byte (no gap, no overrun).
Copies of one form have the same `shape_sha256` (instruction bytes with rel32
and RIP displacements masked), so A1/A2 and B1/B2/B3 are the same code placed
at different addresses. The three VARIANTS slices hold the same 92 names in the
same order (checked by the tool; RELATIVE relocations give the string pointers).

Entry and length switch (human-readable excerpt, A1, from objdump; the
evidence files are produced from bytes):

```
2b99100: push %r14 ; push %rbx ; sub $0x18,%rsp      (form B: sub $0x38,%rsp)
2b99107: mov  %rdi,%rax                             out pointer is also the return value
2b9910a: lea  -0x4(%rdx),%rcx ; cmp $0x24,%rcx ; ja 2b9cd2a
2b99118: lea  table(%rip),%rdi ; movslq (%rdi,%rcx,4),%rcx ; add %rdi,%rcx ; jmp *%rcx
2b99128: cmpb $0x6e,(%rsi) ; jne ... ; cmpb $0x6f,0x1(%rsi) ; ... ; movw $0x0,(%rax) ; ret
```

- Input is `(rsi, rdx)` = byte pointer and length, output buffer in `rdi`.
- `length-switch.tsv`: 37 table entries for lengths 4..40. 27 lengths have a
  compare arm, the other 10 (26, 27, 31, 33..39) go straight to the error tail;
  lengths below 4 or above 40 take the unsigned `ja` to the same tail.
- Inside an arm the code switches on one byte (`movzbl` + `cmp`/`je` chains, and
  10 more jump tables per copy, one of them indexed by `(b0 - 0x63) ror 1` for
  length 8) and then compares the rest one byte at a time with `cmpb $imm,disp(%rsi)`.
  No `bcmp`/`memcmp` is called (unlike the `visit_str` sibling).
- `names.tsv`: each of the 92 names reaches its own `movw` success store
  (92 distinct store addresses per copy). The stored word is
  `(index << 8) | tag` with tag `0x00` in form A and `0x09` in form B; nothing
  else of the output is written on success.

Error tail (A1 `0x2b9cd2a`, B1 `0x2ba09da`):

```
mov %rax,%r14 ; mov %rsp,%rdi ; call *0x64df640        GOT -> 0x141ca00 (Cow<str> out at rsp)
mov 0x8(%rsp),%rbx ; mov 0x10(%rsp),...                ptr, len of the Cow
A: lea VARIANTS,%rdx ; mov $0x5c,%ecx ; call 0x2cf1360 ; mov %rax,0x8(%r14) ; movb $0x1,(%r14)
B: lea VARIANTS,%rcx ; lea 0x18(%rsp),%rdi ; mov $0x5c,%r8d ; call 0x17fbba0 ; 2x movups 32 bytes -> (%r14)
mov (%rsp),%rsi ; test %rsi,%rsi ; jle done ; mov %rbx,%rdi ; xor %edx,%edx ; call *0x64df4a0   GOT -> 0x635de30
```

- The first word of the Cow is tested as a signed value: a positive capacity
  (owned string) is freed with `(ptr, capacity, 0)`; the Borrowed niche
  (`1 << 63`, negative) is not.
- `lsda-call-sites.tsv`: each LSDA has 3 uleb128 call sites. Only the site
  around the unknown_variant call has a landing pad (A1 `0x2b9cd85`); it frees
  the owned string by the same signed test and calls the `_Unwind_Resume` PLT
  stub (`0x63f0a50`, symbol checked through its `.rela.plt` JUMP_SLOT entry).
  The `from_utf8_lossy` and free calls have no landing pad.

## Implementation and comparison

Independent implementation in `tools/re010_action_variant_bytes_115.py`
(`reconstructed_visit_bytes`, `reconstructed_unwind`) and as Rust-shaped text in
`visit_bytes.rs.txt`. No Rust crate is built; Cargo/two-build comparison:
not yet implemented.

The original bytes are run by a fixed-pattern x86-64 subset interpreter in the
same tool (the node is never executed). Calls are stubs with checked arguments:

- `from_utf8_lossy` (GOT `0x64df640`, RELATIVE target `0x141ca00`) must get the
  input pointer and length; it returns Borrowed for valid UTF-8 and an Owned
  heap copy of the lossy text otherwise.
- unknown_variant must get the lossy text, the copy's VARIANTS slice and 92.
  Form A returns a sentinel box pointer, form B writes a 32-byte marker.
- the free (GOT `0x64df4a0`, target `0x635de30`) must get the owned pointer, its
  capacity and 0.
- unwind mode makes unknown_variant raise; the interpreter resumes at the
  landing pad named by the LSDA call site, and `_Unwind_Resume` must receive
  the in-flight exception pointer.

Cases (`cases.tsv`, `unwind-cases.tsv`) are built from the 92 names read from
the bytes: exact names, every single-byte `+1` change, case flips, truncation,
`s`/NUL/`0xff` extensions, high-bit last byte, valid two-byte and truncated
three-byte UTF-8 tails, and fillers of length 0..48 (`a` and `0xff`). A `=`
column means the copy agrees with the reconstruction.

Negative controls:

- `mutants.tsv`: 12 wrong reconstructions (case-insensitive, prefix match,
  dropped or swapped variant, off-by-one index, ignore last byte, accept
  trailing NUL, strict instead of lossy text, never/always free, match after
  lossy conversion, ASCII fold of the first byte) are all rejected.
- `summary.json` `image_mutants`: 38 one-bit corruptions of compare immediates,
  success stores and the length bound in private copies of A1 and B1 are all
  detected (including out-of-range lengths).
- unit tests: wrong digest, unmapped read, wrong FDE start, wrong VARIANTS slice,
  corrupted compare byte, unwind without a landing pad.

## Results and limitations

| metric | value |
|---|---|
| copies | 5 (form A 2, form B 3) |
| cases per copy | 2,821 (92 ok, 2,405 unknown borrowed, 324 unknown owned and freed) |
| normal-path mismatches | 0 / 14,105 |
| unwind cases per copy | 372; mismatches 0 / 1,860 |
| instructions executed | 3,385/3,385 (A) and 3,387/3,387 (B) in every copy |
| one-to-one success stores | 92/92 in every copy |
| reconstruction mutants killed | 12/12 |
| image mutants killed | 38/38 |
| unit tests | 10/10 |

Limits and unresolved items:

- Callee semantics are modelled, not decoded: the stub for `0x141ca00` uses
  Python's `utf-8`/`replace` decoding as the lossy conversion, and the names
  `from_utf8_lossy`, `unknown_variant` and "free" are inferences from the
  argument shapes and the signed-capacity test.
- The two result forms suggest two deserializer error types: one pointer-sized
  (form A, `Err` tag 1) and one 32-byte enum whose spare tag 9 encodes `Ok`
  (form B, the same callee `0x17fbba0`/`0x2f7fef0` as the `visit_str` matcher
  copies). Which deserializer each form serves is unresolved.
- Which callers reach each copy (and so which wire format uses `visit_bytes`)
  is not measured here.
- `insns.tsv` lists all of A1 and only the error tail and landing pad of B1;
  the other copies are tied to these by `shape_sha256` and by their own
  full-coverage counts in `summary.json`.
- No component gate is advanced by this packet.
