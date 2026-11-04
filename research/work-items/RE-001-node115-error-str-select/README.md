# RE-001: node115 two-variant error-string selector @ 0x14cad10

- Component: foundation / diagnostics. Bounded static research; no reconstruction gate.
- Target: node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `8fd8db6`. New tooling, the arithmetic relation and this documentation are independently authored under root MIT. No inferred unlicensed implementation is copied.
- Question: what does the 40-byte leaf at `0x14cad10` return, and how does it select between its two outputs?

The original Rust name, trait and error-type identity are unproved. The GNU symbol-proximity annotation (`_ZNKSt5ctypeIcE8do_widenEc@@Base-0x487d720`) is a nearest-exported-symbol artifact and does not name this function.

## Measured owner

| Role assigned by this packet | Actual FDE, original ELF VA, half-open | Bytes | Native rows |
| --- | --- | ---: | ---: |
| Error-string selector | `0x14cad10..0x14cad38` | 40 | 10 |

This is an export/binding denominator for one complete FDE, not recovered coverage of a larger type. The body digest, file offset, FDE/CIE extents and the one publishing relocation are all bound to the pinned image; `readelf -wf` independently confirms the FDE extent. Filename spelling alone is replaced by `<authenticated-node115>`; no instruction operand or byte is masked.

## Decoded body

```
movzx ecx, byte [rdi]     ; b = discriminant byte at object+0
mov   rax, rcx
xor   rax, 0x1            ; a = b ^ 1
lea   rdx, [rax+rax*2]    ; rdx = 3*a
add   rdx, 0xe           ; rdx = 3*(b^1) + 14            -> returned length
lea   rsi, [rip+...]      ; rsi = &"invalid length"  (0x464b65, 14 bytes)
lea   rax, [rip+...]      ; rax = &"invalid character" (0x464b54, 17 bytes)
test  rcx, rcx
cmovne rax, rsi           ; rax = (b != 0) ? rsi : rax   -> returned data pointer
ret
```

The function reads a single discriminant byte through `RDI+0` and returns a
`&str`-shaped pair — data pointer in `RAX`, byte length in `RDX`:

| Discriminant `b` | Data pointer | Length `3*(b^1)+14` | Bytes |
| --- | --- | ---: | --- |
| `0` | `0x464b54` | 17 | `invalid character` |
| `1` | `0x464b65` | 14 | `invalid length` |

The two messages are adjacent in `.rodata`: `0x464b54..0x464b65` is
`invalid character` and `0x464b65..0x464b73` is `invalid length`, so the single
17-byte gap between the two LEA targets is exactly the first message's length.
The length is produced without a branch: `b ^ 1` maps the boolean discriminant
to `{1, 0}`, scaled by 3 and offset by 14 to hit `{17, 14}` precisely. The data
pointer is a `CMOVNE` between the two RIP-relative LEAs. The relation is faithful
for the boolean domain `{0, 1}`; the arithmetic is reported, not asserted to be
reachable, for other bytes.

## Dispatch-table slot

The address `0x14cad10` is taken exactly once in the whole image: an
`R_X86_64_RELATIVE` relocation at `0x63f9730` in `.data.rel.ro` with addend
`0x14cad10`. There is no direct `CALL`, tail `JMP` or code-section `LEA` to it.
Its neighbours in that table are sibling function pointers
(`0x14c5840`, `0x14c5a90`, `0x154fbc0`, `0x14c58a0`), so this is an observed
method slot in a dispatch/vtable-like structure. This packet does not recover
the owning trait, the full table layout or any caller; it closes only the local
leaf relation and its single publication site.

## Reproduce and controls

GNU readelf/objdump and Python 3 were used; the ELF is x86-64 data, never a
launched program. From repo root with the materialized target:

~~~sh
python3 -B tools/error_str_select_static.py --output work/error-str-select115
python3 -B -m unittest discover -s tests -p test_error_str_select_static.py -v
(cd research/work-items/RE-001-node115-error-str-select && shasum -a 256 -c MANIFEST.sha256)
~~~

The tool authenticates the full image (size + SHA-256) before any analysis or
native invocation, verifies the complete body digest, the eight semantic opcode
windows, both RIP-relative message LEAs, the two rodata messages, the FDE/CIE
bytes and the single publishing relocation, then emits `records.json`, the
objdump window and the FDE frame line.

Ten focused tests cover regeneration, the enumerated length/pointer relation
over all 256 discriminant bytes, the two bound messages, and byte-level negative
controls: corrupting the `xor 0x1` immediate, the `add 0xe` length base, the
`cmovne` selector, or either message LEA breaks the body digest; flipping a byte
inside `invalid character` breaks the rodata check; corrupting the publishing
relocation's addend breaks the dispatch-slot check.

No reconstructed Rust, complete original ABI, owning trait/error type, caller
closure, captured execution, live service, signing, wallet or chain action is
claimed. Next: recover the owning dispatch table and a caller to establish the
original type association before assigning protocol meaning.
