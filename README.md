# Node115 margin leaf B

Independent `no_std` model of the second margin-table arithmetic leaf in node
#115 (Linux x86-64, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

The complete FDE is `[0x38b5300,0x38b54a9)`, 425 bytes with SHA-256
`5ea2f03724183fab2501f7608a167962b44a01fc8f5888e74c06dcb6dc0899d0`.
The measured relation, after row selection, is:

```text
A = sat_u64(2*N)
B = sat_u64(4*b*c)
result = floor(max(A-B,0) / (6*b))
```

The native body distinguishes the diagnostic routes:

- an input with bit 63 set calls slot `0x64e4ea8`, then uses `A = u64::MAX` on
  local normal return;
- multiplication overflow for `B` selects `u64::MAX` without calling that slot;
- subtraction borrow calls slot `0x64e4ea8`, reloads `b`, and returns zero if
  the helper returns.

Observed anchors:

```text
38b53e6: 78 7e              js    0x38b5466
38b53f7: 49 f7 66 f0        mul   QWORD PTR [r14-0x10]
38b53fb: 0f 80 ...          jo    0x38b5492
38b5401: 48 29 c3           sub   rbx, rax
38b5404: 73 16              jae   0x38b541c
38b5411: ff 15 ...          call  QWORD PTR [rip+...] # 0x64e4ea8
38b5417: 41 0f b6 4e f8     movzx ecx, BYTE PTR [r14-0x8]
38b541c: 01 c9              add   ecx, ecx
38b541e: 48 8d 0c 49        lea   rcx, [rcx+rcx*2]
```

The code models the ordinary returning arm and stable row fields. Cursor
selection, units, source types, panic boundaries and ABI remain out of scope.

Evidence:
`research/work-items/RE-007-node115-position-margin-paths`.
