# node115 four-field signed-action encoder

This crate implements the RE-005 action-wire signed-action body at virtual address
`0x2406120` in the target-bound packet
`research/work-items/RE-015-signed-action-rmp-encoders-115`, which supplies its
digest-bound byte evidence. The target is node
#115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The body writes a map/array header, the supplied action variant, a minimally
encoded hexadecimal `signatureChainId`, the selected `hyperliquidChain`, and
the `wei`/`nonce` unsigned fields. Map mode writes the supplied tag key and
field names; array mode omits them. The evidence packet infers the action name
as `CDeposit/CWithdraw`; the API stays address-oriented and accepts its tag and
variant strings from the caller.

Run `cargo test --manifest-path src/node115-signed-action-four-field/Cargo.toml`
from the repository root. Tests compare complete output bytes for target packet
cases 0, 25 and 300 (including the caller's existing prefix). Case 300 exercises
the 32-byte variant at the MessagePack str8 boundary. The target output hashes
are `66e40da6e6d47af0308678a7983947843f1dba6dd6c8714c7b1a4f7e26266cff`
(case 0), `a3907d5dcd9583e867943d84037558416722f0c023621d4803e78026360975d8`
(case 25), and `0631a23b4c33f63895fe071783dcb786c89b69d3909c75ba2cb4a600991cb098`
(case 300). The crate covers this body only; it does not
encode the other 16 action bodies, implement the external signing/hash path, or
execute the captured binary. It has no external dependencies.
