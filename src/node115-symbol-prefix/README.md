# Node115 unqualified symbol prefix

Dependency-free, independently authored Rust for one conditional prefix in
RE-001/exchange. This is not a full symbol resolver or the original ABI.
The caller must already have selected the unqualified lane at `0x46dbd05`.

`observe(&[u8])` returns a rejection, the actual direct USDC/PURR result, or
`NeedsAllocation` containing the parsed u64 and significant ASCII decimal
bytes observed immediately **before** `0x46dbf19`. No allocator result,
canonical comparison or metadata result is supplied. For example,
`outcomeToken+0` and `outcomeToken00` both produce provisional value0 and
decimal `0`; neither observation means the original resolves that spelling.
The later native comparison rejects those spellings. Side selection and
token metadata lookup remain outside this component.

The prefix is case-sensitive. Its decimal scanner provisionally permits one
initial plus and arbitrarily many leading zeros. Nonempty decimal digits and
nonoverflowing u64 arithmetic are required. The library has no 20-character
input cap: length and numeric overflow differ for long strings of zeros.
The fixed20-byte array is only an owned output representation; its unused
prefix is excluded from the native observation. No original object layout,
allocation lifetime, enum representation or Rust type identity is inferred.

The packet at `research/work-items/RE-001-symbol-prefix-115/` contains the
pre-authorship expected-stream seal, original byte/data controls and a public
owned-source builder. Use Rust1.94.1 and Python with Capstone5.0.6:

```sh
python3 research/work-items/RE-001-symbol-prefix-115/build.py \
  --rustc /absolute/path/to/rustc \
  --output work/symbol-prefix-owned
python3 -m unittest discover -s tests -p test_node115_symbol_prefix.py -v
```

The output directory must be new. The builder compiles the library and input-only
client at opt0 and opt3, compares independently regenerated original expectations,
runs ordinary source tests and compiles semantic mutations. Only hex-encoded
input bytes reach the client, in an empty working directory. Expected values
are comparator-side and, separately, compiled into test executables under
`cfg(test)`; they are absent from the ordinary library/client.

This is finite conditional instruction correspondence on macOSarm64 research
builds, not a source-built Linux node, complete function recovery or exhaustive
source/target equivalence. Captured ELF files are static data and are never
launched. New implementation is MIT. The existing #2576 static owner mapping
is reused with credit; it is not new byte coverage. All acceptance gates stay
false.
