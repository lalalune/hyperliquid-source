# Initial reply routing contract

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `7c369234cef4e5e61d8cf260f6ba7ce949537408`.
Task RE-012, transport / node runtime. Addresses are linked ELF virtual addresses.
This contract precedes the independent Rust routing implementation.

The initial caller FDE is `0x22615b0..0x22689f0`. Its call at `0x22626ec`
reaches the established greeting future `0x2037ac0`. A successful decoded
reply is dispatched at `0x2262e89..0x2262ec0`: native tags 0..2 share index 0,
and tags 3..7 use indices 1..5 of the relative table at `0x3d5ce4`.

The policy flag is the transmitted request's first raw byte. The caller stores
AL at state `+0x40` and `+0x1f1`, then copies a `0x4c0` byte object starting
at `+0x68` to `+0x530`, to its temporary, and through `0x2002760` into the
greeting future at `+0x78`. Thus state `+0x1f1` maps to future `+0x201`,
the previously established first request byte. The same AL is stored at state
`+0x4a`, loaded into R13B at `0x2262d1b`, and preserved for routing. This
does not establish that all 256 byte values are reachable in the original Rust.

| Decoded wire value | Condition on first byte | Next action |
| --- | --- | --- |
| Outer 0, nested hash 0 or 1 | bit 0 set | Further state validation required |
| Outer 0, nested hash 0 or 1 | bit 0 clear | Reject: inconsistent greeting |
| Outer 0, nested hash 2 | any | Reject: inconsistent greeting |
| Outer 1 (three words) | any | Reject: inconsistent greeting |
| Outer 2 | any | Reject: no quorum L1 hash |
| Outer 3 | exactly zero | Continue with the existing stream |
| Outer 3 | nonzero | Reject: inconsistent greeting |
| Outer 4 | any | Reject: peer full |
| Outer 5 | any | Reject: rate limited by peer |

The bit test at `0x22630e6` differs from the whole-byte test at `0x2263fe2`.
Do not normalize the raw byte to a boolean in this API. Reply values do not
alter this initial dispatch; the data-bearing continuation consumes them later.

Rejections are native sentinels MIN+0x2f (full), MIN+0x31 (rate limited),
MIN+0x32 (no quorum), and MIN+0x33 (inconsistent), where MIN is 2^63.
The formatter at `0x4de31e0` and its table `0x713e00` bind the error text.
They are modeled as independent Rust errors, not reproduced ABI values.

Rejected streams reach `0x2253890`, which calls imported `close` for a valid
file descriptor. Outer 3 with zero first byte bypasses that stream drop.
The independent exchange continues to borrow caller-owned I/O: its API must
require the caller to discard the stream on rejection, as for other exchange
errors. It must not claim that generic borrowed I/O can close a file descriptor.

Expose the route separately and compose it with the existing exchange.
Returning the data-bearing route must explicitly require additional state
validation; it is never a peer-acceptance result. Preserve the decoded values
and cursor/charge metadata. No endpoint selection, reconnection, retry timing,
state trust, network operation or node/Docker completion is established here.
