# Node #115 GNU Build ID scan

Independently authored dependency-free no_std Rust reconstructing the complete
402-byte leaf at `0x5c948e0..0x5c94a72` in Linux x86-64 node #115, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`build_id(file, section_headers)` accepts borrowed file bytes and complete
64-byte little-endian ELF64 section records from a previously established
Object view. It returns the first matching GNU/type3 descriptor as a borrowed
slice, including Some(empty). It is not an ELF/Object constructor or a native
ABI model. The selected domain is 64-bit hosts/targets with valid Rust slices.

The scan preserves observed section skipping, permissive <=4 alignment,
8-byte alignment, terminal-NUL trimming and missing-final-padding behavior.
No allocation, system call, target execution or original runtime is involved.
The probe's file-loading/ELF-header extraction is qualification harness only.

Build/format commands and pre-Rust frozen qualification are documented in
`research/work-items/RE-002-elf-build-id-115/README.md`. New Rust and scripts
are MIT. Public std provenance is explicit; no private-code credit is claimed.
