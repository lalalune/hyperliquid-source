# RE-005: node #115 UsdSend domain name and version inputs

- Component ID: `action-wire`.
- Target release: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Claim status: static byte observations for one signing wrapper; the EIP-712 name and version values are inferred from the caller's construction and the already mapped domain helper path. Runtime chain ID, verifying contract, salt, and outer object meaning remain unresolved.
- Scope: identify the name and version bytes passed in the node #115 `UsdSend` signing wrapper. No other actions, signing behavior, current-network compatibility, or component gate is claimed.

This closes two explicit unknown values in the bounded path recorded by [PR #5448](https://github.com/lalalune/hyperliquid-source/pull/5448). [PR #5427](https://github.com/lalalune/hyperliquid-source/pull/5427) records the domain type-string helper but leaves its input values unresolved; #5448 records the final digest call chain and synthetic vector but likewise leaves the runtime domain values open.

## Evidence

All addresses are linked ELF virtual addresses. The unique unwind FDE extent containing the wrapper is `[0x44338b0,0x4433c1b)` (875 bytes). An FDE is an unwind range, not a validated function boundary. `disassembly.txt` retains the complete extent from Apple LLVM objdump 21.0.0.

At `0x44338c6`, the wrapper requests a 26-byte buffer. It loads 16 bytes from `0x7d2fef` into output offset `+10`, then loads 16 bytes from `0x7d2fe5` into offset `+0`. Those overlapping copies produce exactly 26 bytes: `HyperliquidSignTransaction`. The wrapper requests a one-byte buffer and stores `0x31` (`'1'`) at its first byte. It then places the name pointer and length 26, and version pointer and length 1, in the input record at `rsp+0x40`.

At `0x443399f`, the wrapper passes that record to relocation slot `0x64e2178`, whose `R_X86_64_RELATIVE` addend is `0x169e950`, the domain helper range recorded by #5427. At `0x44339ee`, it calls slot `0x64ea890`, whose relative addend is `0x43d2b20`, the action message-hash helper recorded in #5448. The packet verifier checks both call encodings and both relocation bindings against the authenticated node image.

These observations establish the constant name/version bytes in this wrapper's domain input record. They do not identify the remaining dynamic fields, establish their live values, or prove a runtime digest comparison.

## Reproduce

From the repository root on macOS, after `./scripts/setup.sh` has verified the pinned inputs:

```sh
python3 research/work-items/RE-005-node115-usdsend-domain-name-version/verify.py --self-test
sha256sum -c research/work-items/RE-005-node115-usdsend-domain-name-version/MANIFEST.sha256
make verify
make catalogue-check
make reproduce
```

Expected verifier output records the exact name `HyperliquidSignTransaction`, version `1`, FDE extent, call sites, relocation slots, and unknown dynamic fields. The self-test rejects a changed version instruction and a changed name literal. The captured binary is read only as data; it is not executed or emulated.

`make doctor` was run and exited 2 because GNU `objdump` and `readelf` are unavailable on this macOS host. Apple LLVM objdump 21.0.0 produced the retained disassembly; `make verify` and `make catalogue-check` passed on the pinned inputs. The repository-wide `make test` was not run because its suite includes captured-instruction emulation outside this static-only task. `make reproduce` generated the two inventory outputs under ignored `work/reproduced/`; those transient outputs were removed after the pass. No hosted CI or full-suite result is claimed.

## Implementation and comparison

No production Rust implementation, source-build comparison, runtime behavior vector, or component gate is requested. `verify.py` checks the target digest, unique FDE extent, selected instruction bytes, literal contents, RIP-relative call slots, and relocation addends. It introduces no dependency and never runs target code.

## Results and limitations

- Verified name bytes: 26/26; version bytes: 1/1.
- Verified calls: 2/2; relocation bindings: 2/2.
- Negative controls: changed version instruction rejected; changed name literal rejected.
- Runtime chain ID, verifying contract, salt, optional-field selection, and the outer action-object ABI remain unknown.
- No full component gate is requested. The next question is which caller supplies the dynamic domain fields and whether any of them are selected from runtime chain configuration.
