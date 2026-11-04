# RE-012: Node115 built-in HTTP header-name lookup and writer references

- Component: HTTP dependency evidence for RE-012; RE-002 source-version context.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Claim: bounded static observations and labeled inferences. No progress gate.
- Scope: the standard header-name pointer/length arrays, one leaf lookup, two inline writer references, and an adjacent negative control. No target execution.

## Problem and useful result

A keyword scan found WebSocket header names, but this did not identify WebSocket frame handling. This packet traces their actual relocations and code users. It records 81 standard HTTP names, their separate length array, a 30-byte pointer/length lookup and two writer sites. One adjacent relocation is unrelated panic metadata. This gives the dependency reconstruction a concrete data layout and ABI lead, while preventing a header-name pool from being misreported as a recovered WebSocket codec.

`observed/headers.tsv` gives every selected ordinal, name, length and ELF VA. `observed/records.json` separates observations, inferences and unknowns. The full selected unwind-range disassembly is retained under `observed/`. GNU nearest-export labels are not source function names.

## Reproduce and coordinates

Run the repository's `make doctor` and `make verify` first. The authenticated input is `artifacts/node/115/hl-node`; no executable is launched from that path. Generate the unwind descriptions with `make fde-index`. Reproduce each GNU 2.47 disassembly with the exact flags in `observed/records.json`, from the repository root. Use `objdump -d -M intel --start-address=0x2e768f0 --stop-address=0x2e7690e artifacts/node/115/hl-node` for the leaf.

All addresses are ELF virtual addresses, not raw file offsets or observed runtime addresses. Runtime pointers require the ELF load bias and RELATIVE relocations. The file-backed pointer cells hold zero before relocation. No operand or machine-byte normalization is applied to the observed disassembly. Compiled source home prefixes are omitted from the version-bearing panic path; its full literal SHA-256 remains in the record.

The leaf consumes the low input byte in DIL, scales it by 8, loads the length at `0x620800 +8*ordinal` into RDX and the relocated name pointer at `0x6459df8 +8*ordinal` into RAX. It has no internal bounds check. A valid built-in ordinal is an inferred caller precondition; this is not a new public API or a claim that the target rejects out-of-range ordinals.

The writer's saved ECX byte chooses the normal-name or ASCII-capitalization path. Instructions at `0x2e775b3` and `0x2e77625` write `: ` and CRLF. The inline lookups at `0x2e774ae` and `0x2e77654` use the same tables. Panic descriptors reference vendored `http-0.2.12/src/header/map.rs`; this establishes those source-path observations, not complete encoder ownership or an exact public-source build match.

The contiguous relocation at `0x645a080` is excluded: it names Rust core `time.rs`, and its code user at `0x2e7dad9` is a separate range. Contiguous relocation storage alone is not array or function ownership evidence.

## Necessary research unblock

The required original `make verify` failed before analysis on this Windows host: Git's MSYS GPG treated native drive paths as relative paths. Native and forwardslash drive forms both failed. The same public key and unchanged GPG flags succeeded with the same Git installation's `cygpath` representation. The small `tools/artifacts.py` change applies that conversion only on Windows when a converter is installed beside GPG. Native GPG without it and POSIX GPG retain their original arguments. No user keyring, private key, agent start, installation or global setting is needed.

The 25 focused artifact/path controls pass. Actual production verification accepts the original signed Node115 data and rejects a one-byte-tampered copy. `make verify` then authenticates both retained artifacts, 29 imported files, all pinned sources and 28 existing packet manifests / 456 entries. The work immediately resumed target FDE and code/data analysis. This is not a standalone tooling-polish or completion claim.

## Limits and remaining work

No independently authored Rust implementation, compiler match, whole-ELF equivalence, original function names, complete callers, application request entrypoint, WebSocket framing, peer behavior or network compatibility is claimed. FDE extents are not a complete function census. Public source licensing and exact private modifications remain dependency-closure work. Component gates remain false.

The independent packet verifier authenticates the target digest, checks relocation/data bindings and actual instruction boundaries, and rejects four structural corruption controls. Run `python -B research/work-items/RE-012-node115-header-name-lookup/verify.py --objdump /absolute/path/to/objdump --self-test` from the repository root. Selecting the captured Node115 as `--objdump` is refused before any tool process. These controls do not establish a Rust reconstruction or runtime equivalence. Final-head repository validation results and original Windows setup failures are reported separately in the PR.
