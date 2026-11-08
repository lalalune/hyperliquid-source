# Node115 element builder

Independent `no_std` value projection of the one per-field 0xb0-byte element
construction recovered by RE-006. It sets the +0x40/+0x60 product fields to
zero, writes scale `10^14` at +0x58 and +0x78, and copies the source tail into
+0x80..+0xa0.

The original source element type, ownership, allocator, generic builders and
join/callee effects remain out of scope.
