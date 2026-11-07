Static verifier: three complete bodies, 3,144 bytes / 795 instructions; 18
operative mutations rejected; 65,536 conditional mode/choice cases, zero
mismatches. Masked clone comparison agrees, excluding only CALL rel32 operands.
Target not executed. Integer writer and allocator callees remain opaque.

Validation host: Windows, Python with Capstone 5.0.6 / pyelftools 0.32.
Full native-tool tests/reproduction remain unqualified: readelf, objdump, Rust
and Ghidra are unavailable on PATH; signature verification needs GPG on PATH.
Focused static checks and catalogue/manifest consistency are not a full-suite
or binary-equivalence claim. Catalogue count records packet existence only.
