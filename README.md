# Node115 Variant A cursor

Independent `no_std` model of the 22-key u64 cursor search at node #115
`[0x35bd660,0x35bd6f2)`. Target SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Retained body facts:

- size 146 bytes;
- SHA-256
  `3da45a31a814e5cb8c3b77323c8c550b760ad8a76aadc94048d13e54a3c16950`;
- count word at node `+0xba`, u64 keys at `+0x8`, child edges at `+0xc0`;
- at most 22 keys per node;
- the record has flag `+0`, node `+8`, remaining height `+0x10` and position
  `+0x18`;
- flag zero returns the in-node scan position; flag one is the exhausted-height
  route with position equal to the node count.

Exact target anchors:

```text
35bd660: 48 89 f8                 mov    rax,rdi
35bd663: 48 8b 09                 mov    rcx,QWORD PTR [rcx]
35bd666: 44 0f b7 86 ba 00 00 00  movzx  r8d,WORD PTR [rsi+0xba]
35bd685: 48 3b 4c fe 10           cmp    rcx,QWORD PTR [rsi+rdi*8+0x10]
35bd68a: 41 0f 97 c2              seta   r10b
35bd68e: 41 80 da 00              sbb    r10b,0x0
35bd6cc: 48 8b b4 fe c0 00 00 00  mov    rsi,QWORD PTR [rsi+rdi*8+0xc0]
35bd6d9: 31 c9                    xor    ecx,ecx
35bd6eb: b9 01 00 00 00           mov    ecx,0x1
```

This crate models only Variant A. Node allocation, malformed native pointers,
the sibling 11-key layouts, caller semantics and original ABI remain outside
scope.

Evidence:
`research/work-items/RE-006-node115-variant-cursor`.
