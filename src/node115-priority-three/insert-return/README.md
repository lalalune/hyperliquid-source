# Node115 shared insert return contract

Independent `no_std` model of the slab-slot return contract shared by node #115
bodies `[0x58df360,0x58df78b)` and `[0x58df790,0x58dfbbb)`.

Target SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

| Owner | Bytes | SHA-256 |
| --- | ---: | --- |
| `0x58df360` | 1,067 | `9885b0a31f873965b33690748e029b2539e0398c6e9d48f1eca3a5dc61f96e29` |
| `0x58df790` | 1,067 | `1c933868b0d8b192a97c7454766e2b0b3dfd17879d851ed5a0d58ab9c6a2d077` |

Both bodies are called twice by their ring-append twin and return the
pre-insert slab head in `rax`. The measured collection header is:

```text
+0x00 capacity
+0x08 buffer
+0x10 length
+0x18 counter
+0x20 head
```

The return cases are:

- `head == length`: append at `head`, then set length and head to `head + 1`;
  if `head == capacity`, the slab grow helper runs first.
- `head < length` and `buffer[head].first_dword == 2`: reuse the vacant slot,
  copy its `+0x8` link into head, and return the old head.
- `head > length`, or a non-vacant reuse slot: run the expected-vacant-entry
  panic and trap.

Exact anchors from `0x58df360`:

```text
58df53b: 4d 8b 6e 20        mov  r13,QWORD PTR [r14+0x20]
58df544: 49 8b 6e 10        mov  rbp,QWORD PTR [r14+0x10]
58df548: 49 8b 46 18        mov  rax,QWORD PTR [r14+0x18]
58df54c: 48 ff c0           inc  rax
58df556: 48 0f 45 c8        cmovne rcx,rax
58df55a: 49 89 4e 18        mov  QWORD PTR [r14+0x18],rcx
58df55e: 49 39 ed           cmp  r13,rbp
58df561: 0f 85 a8 00 00 00  jne  0x58df60f
58df5a6: 49 8d 6d 01        lea  rbp,[r13+0x1]
58df5aa: 49 89 6e 10        mov  QWORD PTR [r14+0x10],rbp
58df5ae: 49 89 6e 20        mov  QWORD PTR [r14+0x20],rbp
58df620: 83 3c 07 02        cmp  DWORD PTR [rdi+rax*1],0x2
58df62d: 48 8b 47 08        mov  rax,QWORD PTR [rdi+0x8]
58df631: 49 89 46 20        mov  QWORD PTR [r14+0x20],rax
58df6c3: 4c 89 e8           mov  rax,r13
58df6d7: c3                 ret
58df709: ff 15 a9 ff bf 00  call QWORD PTR [rip+0xbfffa9] # 0x64df6b8
58df70f: 0f 0b              ud2
```

The panic message is `expected vacant entry ` at `0x4339b2`; its source
Location is `l1/src/slab/slab.rs:78:21`. The model stops at the slot-return
contract and does not model the event-record copy, order rewrite, link writes,
allocation helpers, ABI or unwind behavior.

Evidence:
`research/work-items/RE-006-node115-shared-insert-return`.
