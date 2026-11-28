# Four-limb decimal conversion and its caller result

The crate `src/node115-u256-decimal-scale` reconstructs the observable result and input mutation at image VA `0x434f910` in node 115. The prior [exchange token decimal scaling packet](../exchange-token-decimal-scaling-115/README.md) established the arithmetic and recorded samples. This change supplies reusable Rust source and connects both call sites in `0x42100c0` to the output record that consumes the amount.

The pinned `artifacts/node/115/hl-node` is 105896032 bytes with SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The original executable is read as data.

## Arithmetic and ownership

The input at RDX is four little-endian 64-bit limbs. SIL is a signed decimal exponent. The power of ten must fit in a u64, giving an inclusive exponent range of -19 through 19. A negative exponent multiplies a copy of the input by the power, with a four-limb overflow check. A nonnegative exponent divides the input in place, rounding down. Zero follows the division-by-one path. The final comparison is unsigned and strictly below `0x0ccc_cccc_cccc_cccc`. A rejected quotient is still visible in the input buffer. An unsupported exponent leaves the buffer alone. RDX has no defined payload on refusal. The host interface represents these cases with `Option<u64>`.

The Rust implementation uses limb-by-limb arithmetic with a u128 intermediate. The native general-purpose big-integer routines also support wider factors and divisors. Only the single-limb power produced at this call boundary is exposed here.

## Caller evidence

The relative relocation at `0x64e7ec0` points to the scaler. The packet pins five indirect calls through this slot. Two occur in `0x42100c0` and converge at the same result publication:

* At `0x4210259` the caller supplies exponent 10 and at `0x421025e` passes the four-limb stack buffer. At `0x4210264` it checks the option tag in RAX.
* The second arm loads a byte at `0x421049f`, copies a 32-byte value into scratch at `0x4210614` and passes the byte in ESI to the call at `0x4210643`. Only its low byte participates in the signed exponent conversion.
* Either refusal reaches `0x4210695` and writes tag zero at output offset 0. Either success reaches `0x4210689`, stores RDX at output offset +0x30 and writes tag one. A valid zero amount is therefore distinct from refusal. No payload bytes should be read from the rejected result.

The other three slot references identify consumers without assigning their result schemas here. The neighboring metadata routines at `0x46aa2e0` and `0x3c201e0` accept scalar operands and are outside this four-limb interface.

## Reproduction

```sh
python3 research/work-items/RE-007-node115-u256-decimal-source/verify.py --target artifacts/node/115/hl-node
cargo test --offline --manifest-path src/node115-u256-decimal-scale/Cargo.toml
```

The first command checks target identity, instruction bytes and relocation bindings using Capstone and pyelftools. The second compares both outputs against 7,266 cases computed by Python arbitrary-precision integers. The corpus covers all 256 exponent bytes, limb carries and remainders, four-limb overflow, strict-bound neighbors, accepted zero and the post-refusal contents of the input. The recorded windows cite existing ranges for reproducibility.

## Integrated exchange regression

The standalone scaler preserved its input during multiplication. At base
`2da45cb0a761cff6b478e40421699857d87a94df`, the integrated
`exchange::token_scaling::signed_exponent_scale_u256` wrote the product back.
With input 50 and exponent -2 both returned 5,000. The integrated caller then
held 5,000, so dividing its buffer by ten on a second call returned 500.
The corrected integrated client keeps 50 after multiplication and returns 5
on the second call. On the division path, narrowing can refuse the result
after the caller's buffer has already received the quotient.

The [public API client](exchange_client.rs) compares both the returned amount
and all four resulting limbs against the existing arbitrary-precision oracle.
Across 7,266 rows, the base differed in 82 successful calls and 501 refusals.
Its return values agreed on every row. The integrated correction agrees on
both outputs for every row in debug and release. The [retained results](exchange-results.json)
include the corpus digest and the two-call example.

From the repository root, use Python 3.12 or later, Git with the base commit
available, and rustup with Rust 1.95.0 already installed.

```sh
python3 research/work-items/RE-007-node115-u256-decimal-source/exchange_replay.py
```

The replay extracts the base commit's `src/` tree into a temporary directory,
compiles an ordinary `exchange` consumer separately against that tree and the
current checkout, and verifies the frozen report. Both Cargo profiles run
offline. The base comparison requires only the repository's source history.
