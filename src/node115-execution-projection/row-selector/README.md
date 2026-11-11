# Node115 execution-state 32-byte row selector

Independent `no_std` model of the 32-byte result-row traversal in node #115
FDE `[0x2af7150,0x2af77ee)` (1,694 bytes, SHA-256
`9a3489a933e479e7e732196a69289e100a48c282589953df8468b7af4383e9f7`).
Target SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The measured traversal:

- walks rows with a 32-byte stride;
- loads each row's first qword;
- compares current and candidate first words as unsigned;
- when the words differ, keeps the current row only when it is larger;
- when the words are equal, calls suffix comparator `0x23316c0`;
- a signed comparator result greater than zero keeps the current row, while
  equality or a negative result replaces it with the later candidate.

Exact anchors:

```text
2af756d: 49 8b 0e        mov  rcx,QWORD PTR [r14]
2af7570: 49 8b 17        mov  rdx,QWORD PTR [r15]
2af7573: 48 39 d1        cmp  rcx,rdx
2af7576: 0f 97 c0        seta al
2af7579: 1c 00           sbb  al,0x0
2af7588: e8 33 a1 83 ff  call 0x23316c0
2af758f: 7f cf           jg   0x2af7560
2af7591: 4d 89 fe        mov  r14,r15
```

Only pointer selection is modeled. Row semantics, suffix ordering, the separate
64-byte traversal and downstream state writes remain open.

Evidence:
`research/work-items/RE-008-node115-execution-projection`.
