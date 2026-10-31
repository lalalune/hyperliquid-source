# Re-dump notes (2026-10-31, release 94, verified binary)

Binary: SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f,
GPG fingerprint CF2C2EA3DC3E8F042A55FB6503254A9349F1820B, from the
provenance recovery URL. The repo path contains only an LFS pointer
on this machine, so re-dumps were done from the verified copy.

- 0x20a458 bytes, first 16: `aws_namecapacity`
  (first 8 = `aws_name`, next 8 = `capacity`, a different field name).
  This is the 8-byte compare target at 0x164eae7-0x164eafa.
- Mapper discriminants, extracted from the variant_mapper window
  (movb $imm, 0x1(%rbx) lines, distinct values, sorted): 76 values,
  exactly 0x00-0x4b, including 0x20 (NvTestnet).
- String scanner FDE: 0x4ebfd80-0x4ec0072, full window retained in
  disassembly/string_scanner_4ebfd80.txt (previous version was
  truncated at 0x4ebfe10).
- String decoder FDE: 0x4ebf970-0x4ebfc06, full window retained in
  disassembly/string_decoder_4ebf970.txt. It also contains a
  backslash compare at 0x4ebf9f4 (cmp $0x5c) followed by a call
  to an escape decoder at 0x4ebef70, not a reject.
- Repository checks, recorded honestly, not claimed as passed:
  `make test` = 195 tests, 7 failures, 82 errors, 6 skipped
  (pre-existing, LFS-pointer related, unrelated to this work-item);
  `make catalogue-check` fails at elf_index with
  "Expected ELF64 little-endian input" (LFS pointer, not ELF);
  `make verify` fails at artifacts/node/115/hl-node (LFS pointer);
  `make doctor` fails on missing optional tools (llvm-objdump,
  java, rust toolchains, git-lfs, Ghidra).
  `check_evidence.py` (this work-item only) = PASS, with and
  without --binary.
