# Node115 margin leaf A

Independent `no_std` model of the first margin-table arithmetic leaf in node
#115 (Linux x86-64, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

The complete FDE is `[0x38b54b0,0x38b55f3)`, 323 bytes with SHA-256
`e2a38bc8106d8f383df9a66180c06f9a138e0bfb8235cde403971c2427736f4a`.
After the predecessor cursor selects a row, the native body reads:

- row byte `-8` as `b`;
- row qword `-0x10` as `c`;
- computes `floor(N / (2*b))`;
- subtracts `c`;
- on unsigned borrow, calls diagnostic slot `0x64e4ea8` and returns zero if
  that helper returns.

Observed anchors in the retained evidence packet:

```text
38b5592: 0f b6 71 f8        movzx esi, BYTE PTR [rcx-0x8]
38b55a6: 48 f7 f6           div   rsi
38b55a9: 48 2b 41 f0        sub   rax, QWORD PTR [rcx-0x10]
38b55b8: ff 15 ea f8 c2 02 call  QWORD PTR [rip+0x2c2f8ea] # 0x64e4ea8
38b55be: 31 c0              xor   eax, eax
```

The code models the ordinary returning branch only. Cursor lookup, source-level
field names, original units, ABI and diagnostic-helper effects remain open.

Evidence:
`research/work-items/RE-007-node115-position-margin-paths`.

`ZeroScale` is a safe host refusal for `b == 0`; the native division-by-zero
path is outside this ordinary-returning arithmetic model.
