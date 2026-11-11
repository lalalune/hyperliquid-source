# Node115 u64 cursor search

Independent `no_std` projection of the selected u64 B-tree cursor search at
node115 `0x1d65920..0x1d659af` and its byte-identical clone.

`Node::new` validates at most eleven strictly ascending keys and `n+1` child
slots. `search` returns the final borrowed node, whether the key matched,
remaining logical height and equal/insertion position. It does not reproduce
the native pointer record, malformed trees, ownership or downstream callers.
