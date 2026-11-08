# Node115 element argument staging

Independent `no_std` models for the wholesale `0xf8 -> 0xb0` element staging
forms recovered by RE-006: a prefix copy and a tag+tail copy that together cover
the same first 0xb0 bytes.

Incoming-argument forwarding, per-field construction and the original helper
record types remain separate boundaries.
