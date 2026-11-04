# node115 command program and argument construction

Independently authored MIT `no_std` + `alloc` reconstruction of the selected
**normal-return** program/argument state. `Command::new` classifies the original
program bytes, converts or substitutes them, and owns separate program and
argv[0] buffers. `push_argument` owns each new argument, preserves a sticky NUL
flag, and maintains actual pointers plus a final null pointer.

`arguments_with_nul()` includes argv[0]. The raw kind values are 2 for a leading
slash, 1 for another slash, and 0 otherwise; backslash is ordinary data here.
Interior NUL selects `<string-with-nul>\0` while preserving the classification
of the original program. This library does not launch a process or implement
the whole native Command layout, environment, stdio, allocator or unwinder.

The real local Cargo dependency in `cstring/` is an immutable MIT snapshot of
`node115-owned-cstring`, pinned by source digest and contribution head in
`cstring/ORIGIN.json`; its original LICENSE is retained. No placeholder or
registry substitute is used, and primitive credit stays with that contribution.
See `research/work-items/RE-012-command-construction-115/README.md` for target
bytes, frozen expectations, actual qualification and remaining boundaries.
