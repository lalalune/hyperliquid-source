# RE-012: node115 typed TCP prefix

This static evidence packet closes the inner typed prefix left opaque by the
existing TCP result-boundary packet. The reader consumes a raw Boolean, a u32
index accepted only as `BroadcastGroup`0/1, then a u32 index accepted only as
`TcpId`0. It establishes the active result fields, exact cursor and logical
charge transitions, fail-fast precedence and trailing-input acceptance. The
Boolean's domain field name and the names of accepted group variants are not
recovered.

Target: Linux x86-64 node115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Research base: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Result and limits

- Mode DWORD1 charges1 before reading the Boolean. Charge overflow leaves the
  count unchanged; exceeding the limit retains the increment. A present byte
  is consumed before its unsigned0/1 validity test.
- Each subsequent scalar charges4 before reading. Group rejection prevents
  the TcpId read. Scalar failures retain their own and all preceding cursor
  and charge changes.
- Successful parsing increments a limited reader's count by9. Its encoded
  prefix length is exactly one of3,5,7,9,11 bytes, since each scalar uses1,3 or5.
  Nonminimal scalar encodings are accepted. Trailing bytes
  remain in the slice; no end-of-input requirement is imposed.
- Invalid scalar markers consume nothing on the fast route, which requires
  remaining>4, but consume their marker on the short route. Appending bytes can
  therefore change the cursor position of a failed parse.
- The caller projection is restricted to incoming R8D=0. It initializes a
  fresh limited reader with count0 and the supplied limit/input. It still calls
  opaque timer helpers; normal return and preservation of the live input,
  output and frame are explicit premises.
- The credited outer reader publishes the original full frame length on
  typed success. That word is neither consumed-prefix length nor logical
  charge. Formatting, cleanup, allocation, asynchronous state and timer effects
  remain outside this projection.

Only active fields are meaningful. Native error paths copy inactive register
or stack bytes, and success initializes only its tag and two bytes. This packet
does not define a deterministic raw32-byte result object or recover a Rust ABI.
The full premises and address-by-address reasoning are in [PROOF.md](PROOF.md).

## Evidence scope and prior work

| Role | Complete half-open FDE | Bytes |
| --- | --- | ---: |
| Inner composition | `0x2ce1590..0x2ce172e` | 414 |
| Fresh-reader wrapper and retained context | `0x2700010..0x27005d1` | 1,473 |
| Credited outer reader | `0x2b79e30..0x2b7a0a3` | 627 |
| Error-conversion boundary | `0x2b7a0b0..0x2b7a140` | 144 |
| Credited u32 wrapper | `0x2cd79c0..0x2cd7ab3` | 243 |
| Credited u32 short reader | `0x5822490..0x58225b5` | 293 |
| Credited raw error constructor | `0x5822700..0x582270e` | 14 |

These seven extents total3,208 bytes. They describe the evidence denominator,
not implemented coverage or newly discovered bytes. All evidence derives from
one pinned capture; fresh static decoding is not an independent runtime oracle.

The baseline u32 packet credits the shared raw error constructor to
[PR2300](https://github.com/lalalune/hyperliquid-source/pull/2300). This is
historical attribution: the recorded current direct remote lookup returned404
and is unavailable, so no live PR status is inferred. [PR2412](https://github.com/lalalune/hyperliquid-source/pull/2412)
and the [u32 reader packet](../RE-005-node115-u32-varint-reader/README.md)
establish charge, markers and shortfall behavior.
[PR2572](https://github.com/lalalune/hyperliquid-source/pull/2572) and the
[outer TCP packet](../RE-001-node115-tcp-typed-result-boundary/README.md)
establish the typed-result/original-length boundary while leaving the decoder
opaque. The new result is their concrete inner composition and conditional
caller relation.

[PR2902](https://github.com/lalalune/hyperliquid-source/pull/2902) owns the u32
Rust reconstruction and was open at the recorded ownership review. This packet
does not duplicate, copy or execute that implementation or its evaluator.
No Rust implementation is added here.

## Validation and interpretation

[VALIDATION.md](VALIDATION.md) is the record of actual commands, tool identities,
regeneration comparisons, focused controls and failures. Manual examples in
the proof are deductions from the retained branches, not executed fixtures or
an independent behavioral reference. Byte-corruption controls qualify the
binding of decisive operands and data; rejection of a changed byte does not
execute or establish behavior of a mutated target.

The evidence does not establish whole-network decoding, machine-code/source
equivalence, diagnostic strings, physical reclamation, original public types,
nonzero instrumentation/TLS behavior, hosted CI or live operation. No progress
gate is completed. Newly authored analysis and checking code use the root MIT
license; existing MIT scaffolding and prior packets retain credit. The captured
artifact is research input and is not relicensed as independently authored
source. No unlicensed inferred implementation was copied.

The next source question is whether, after PR2902 is integrated or reuse is
separately agreed, its real scalar API can support this typed result together
with exact remaining-slice and charge state. Nonzero instrumentation and
formatter/drop behavior require separate native evidence if a concrete caller
needs those effects.
