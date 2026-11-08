# Node115 metadata kind

Independent `no_std` model of the two metadata-shaped predicates used by the
node #115 checkpoint lifecycle. Target SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The measured predicates are:

| FDE | SHA-256 | Comparison |
| --- | --- | --- |
| `[0x1500a60,0x1500b83)` | `5dd7ac6a1971eab295f33940c9734fc7cdccf64be747f53e92ca31a746d463b4` | `(mode & 0xf000) == 0x4000` |
| `[0x1500d20,0x1500e43)` | `d5fc38bd3f523509186d003072bb9922db7ab2ec613f6fb2edbbb4365d22b895` | `(mode & 0xf000) == 0x8000` |

Exact target anchors:

```text
1500b1a: b8 00 f0 00 00  mov eax,0xf000
1500b1f: 23 44 24 48     and eax,DWORD PTR [rsp+0x48]
1500b23: 3d 00 40 00 00  cmp eax,0x4000
1500b28: 0f 94 c0        sete al

1500dda: b8 00 f0 00 00  mov eax,0xf000
1500ddf: 23 44 24 48     and eax,DWORD PTR [rsp+0x48]
1500de3: 3d 00 80 00 00  cmp eax,0x8000
1500de8: 0f 94 c0        sete al
```

The model classifies only the metadata `st_mode` word. The metadata helper,
filesystem errors, repeated calls, race behavior and the surrounding checkpoint
plan are intentionally outside this crate.

Evidence:
`research/work-items/RE-009-node115-checkpoint-lifecycle`.
