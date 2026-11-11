# Node #115 clearinghouse notional ratio

Dependency-free `no_std` model of the body at `0x44dcf80..0x44dd1a4`.

The record index is `key % 10000`. A negative record field or an overflowing
signed product takes the `clearinghouse.rs:179` edge. A zero denominator
returns the absent tag and leaves the balance unchanged. Otherwise the body
scales `abs(product) / denominator` by the signed scale with binary64
division then multiplication, truncates that finite result into a saturating
`i64`, and saturates both `converted - product` and `balance - converted`.

See `research/work-items/RE-007-node115-clearinghouse-ntl-ratio` for the
digest-bound exports. This crate does not reproduce the panic ABI, the caller
loop, or a full clearinghouse.
