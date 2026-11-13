# RE-005: node #115 event context identifier `0x421dc00` and its spot-deploy call site

Without this packet, the 32-byte buffer that the spot-deploy charge body `0x2c57090` hands to its event helper exists only as a stub (`exchange-spot-deploy-charge-115` replaces `0x421dc00` by an injected value). With it, there is an independent Rust model of that function (static): from the three values the call site loads (state words at `+0x28` and `+0x08`, a mode byte at `+0xb9a`; this argument layout was already recorded by the spot-deploy packet) it computes the 32 bytes as one of three base-byte constructions chosen by mode and thresholds, then an overlay of the inputs' own bytes from offset 10. This is a static reconstruction: the node was never run and no function of it was executed, no behavioural equivalence with it is claimed, and nothing here shows what the event helper does with the buffer or any state change. The existing spot-deploy model is unchanged and still injects the buffer; the new function is not wired into it.

- Component ID: `exchange` (spot deploy) with the shared encoder pieces; RE-005 / RE-010 boundary.
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked first by `verify_target.py`).
- Source commit: repository `a8616af94`; no reference source consulted or copied.
- Claim status: addresses, constants, branch conditions, offsets and relocation targets are observations from bytes. The roles named below (mode, `a`, `b`, `c`, context, Uint token, MessagePack tuple) are inferences. The expected values are a separate model of the same reading, not a node run.
- Scope included: `0x421dc00` (1,393 bytes), `0x44e6af0`, `0x38d3100`, `0x41d4eb0`, and the register/offset mapping at the call site `0x2c574be` with its zero-buffer alternative.
  Also read: the same call-site pattern in the two sibling charge bodies `0x55cbcc0` (call `0x55cc0de`, mode byte at `+0x170a`) and `0x55cc610` (call `0x55cca2e`, mode byte at `+0xb9a`).
  Excluded: what `0x421dc00`'s other 123 callers pass, the event helper behind slot `0x64e6ad0`, the meaning of the inputs, allocation failure and the panic path at `0x38d329f`, and everything listed as credited below.
- Crate: [`src/node115-event-context-id`](../../../src/node115-event-context-id/README.md) (cross-reference both ways).

## Credit: what already existed

Searched by address and name in `research/`, `src/`, `tools/`, `docs/`. None of this is counted as new here.

| Area | Prior work | Used how |
| --- | --- | --- |
| Spot-deploy charge body `0x2c57090`, its layout (`b9a`, `[state]==1`), the call-site argument placement (mode byte `b9a`, state words at `+0x28` and `+0x08`, third argument 0) and the zero buffer when the state tag is not 1 | `research/work-items/exchange-spot-deploy-charge-115`, `tools/spot_deploy_charge_115.py` (input layout at lines 243-246, expected call at line 411, conditional zero path at lines 410-414); source location `RE-001-node115-loc-edge-2c5789d` | consumer and source of the call mapping; that packet stubs `0x421dc00` ("context reader"). The mapping and the zero path are its finding, not new here |
| Panic location `0x38d329f` (`l1/utils.rs`) | `RE-001-node115-loc-edge-38d329f` | cited only |
| Other direct callers of `0x421dc00` | `RE-017-abci-postblock-keys-115` (edges `0x56019b2`, `0x5601c22`), `tools/element_argument_static.py` windows | not analysed here |
| MessagePack unsigned writer `0x3d517e0` and width helpers | `RE-015-rmp-write-uint-b-115` (Python model); `RE-017-abci-root-tree-115` (`0x41d2670` element step, `0x41d3f60` fast end); `serialization-rmp-newtype-forward-115` (array header `0x3d50270`, end `0x41d3f60` as dependencies) | their findings taken as given; bytes re-pinned, call chain from `0x41d4eb0` read |
| ABI encoder `0x169e350`, `0x169dcc0`, `0x169df80`, `0x169e1d0` | `RE-005-bridge-static-framing-115`, `RE-005-node115-bridge-preimage` (Address/FixedBytes tokens, 64-byte flatten); `RE-002-node115-rust-ethabi-encoding-bindings`; census and `byte-windows.json` class `0x169de60` as public `ethabi` | boundary; only the Uint arm and table entries are added |
| Keccak sponge `0x5cda910` / `0x5cdad40` | `evm-keccak-ripemd-hash-115`, `RE-001-node115-noop-preimage`, `RE-005-node115-bridge-preimage` | boundary; rate/delimiter at three init sites read here |
| Permutation Rust | `src/node115-sponge-permutation` (`RE-009-sponge-permutation-115`) | unchanged path dependency |

`0x421dc00`, `0x44e6af0`, `0x38d3100` and `0x41d4eb0` have no overlap with `research/work-items/RE-002-node115-vendor-census/census.json` or `research/byte-windows.json` (checked by address range). That absence is not proof they are not library code.

## What is new

1. The whole body of `0x421dc00`: branch selection, the arithmetic construction, and the overlay with its fit rule for the third value.
2. `0x44e6af0` (three unsigned tokens, low limb only) and the Uint arm `0x169dfd4` with its two table entries.
3. The composition `0x38d3100` → `0x41d4eb0` (empty vector, array of three, Keccak-256) as one flow.
4. The finding that the mode byte is only a branch selector: it is neither hashed nor written to the output. (The call-site mapping at `0x2c57499..0x2c574c3` / `0x2c57776` is the prior tool's; here its bytes are only re-pinned.)
5. Rust implementation of items 1-4, with its oracle, byte verifier and mutation runner.

## Evidence (observations)

Arguments of `0x421dc00`: `rdi` out, `sil` mode, `rdx` a, `rcx` b (saved at `[rsp+0x28]`), `r8` c. All three values are `u64`.

| Where | What |
| --- | --- |
| `0x421dc17..0x421dc26` | `cmp sil,2; jae`: mode 0 and 1 go to the arithmetic construction |
| `0x421dcd2..0x421dcf9` | mode exactly 2: `a > 0x19067a34` arithmetic; else `a >= 0xdf59bc0` MessagePack; else ABI |
| `0x421de1b..0x421de35` | mode above 2 (3..255): `a > 0x2a166de8` arithmetic; else `a <= 0xd377be0` ABI; else MessagePack |
| `0x421dc26..0x421dcba` | arithmetic: `s=(a*K+b)*K`, then four words `rotl20((seed*K + c + s)*K)` stored big-endian; `K=0xf1357aea2e62a9c5`, seeds `0x89abd75173154e28`, `0xea62407ff1ea5bb8`, `0xb1825c50e63ce358`, `0x78c3727a71762f98` |
| `0x421dcf9..0x421dd1a`, `0x44e6af0` | ABI: `a,b,c` to three tokens (tag byte 4, low limb set, other limbs 0) → slot `0x64e0140` = `0x169e350` |
| `0x169dfd4`, tables `0x47b72c`, `0x47b754` | tag 4 is one head word: the four limbs byte-swapped, limb 3 first → a big-endian 256-bit word |
| `0x421de35..0x421de60`, `0x38d3100`, `0x41d4eb0` | MessagePack: `[rsp+0x80..]=a,b,c`; empty `Vec`; array header length 3 (`0x90 \| 3 = 0x93`), then `a`,`b`,`c` through the unsigned writer in order; result tag `0x8000000000000004` is Ok |
| `0x3d517e0` (+ width helpers) | `< 0x80` one byte; `< 0x100` `0xcc`; `< 0x10000` `0xcd`; high 32 bits zero `0xce`; else `0xcf`; payload big-endian |
| `0x421dd8f`, `0x38d31cd` | sponge init: rate `0x88` (136), delimiter byte 1; absorb slot `0x64e0148` = `0x5cda910`, copy `0xe0`, squeeze slot `0x64e0150` = `0x5cdad40` for 32 bytes. The ABI path hashes the encoder's bytes, the MessagePack path its `Vec` |
| `0x421de63..0x421e13f` | overlay on the 32 base bytes: `len(a)` at byte 10, `a` without leading zero bytes (zero has length 0); then `len(b)`,`b`; then `len(c)`,`c` only if `za+zb+4 >= 9-zc` (zN = leading zero bytes of N), i.e. if it fits before byte 32. Unwritten bytes keep the base. The result is not the bare digest |
| `0x2c57499..0x2c574c3`, `0x2c57776` | prior work, re-checked against the bytes: if the `u32` at the state start equals 1: `a=[state+0x28]`, `b=[state+8]`, mode `=byte [state+0xb9a]`, `c=0` → `0x421dc00`; otherwise 32 zero bytes. The buffer is then the fourth argument of the event helper slot (`0x2c577c8..0x2c577fd`) |
| `0x55cc0b9..0x55cc0e3`, `0x55cca09..0x55cca33` | the same 42-byte pattern in the sibling bodies `0x55cbcc0` (mode byte at `+0x170a`, matching `LAYOUT_B` of `tools/spot_deploy_charge_115.py`) and `0x55cc610` (`+0xb9a`); the crate function takes the mode byte as a parameter, so it covers all three |

`objdump -d -M intel --start-address=0x421dc00 --stop-address=0x421e171 artifacts/node/115/hl-node` (and the other ranges in `verify_target.py`) shows each line. The verifier pins 65 byte windows (15 whole functions by SHA-256), 4 relocation slots and the 9 constants the crate uses.

Also observed, not covered by a packet tool: `objdump -d -M intel --no-show-raw-insn -j .text artifacts/node/115/hl-node | grep -c -E "call +421dc00 "` prints 126 direct call sites. A throwaway scan of the nearest write to `r8` before each call found 120 sites that zero it and 6 that load it from `[reg+0x58]`. That shows only that the register is loaded from memory at those six sites; whether a non-zero value is reachable there is not shown. The spot-deploy site passes 0.

## Inferences

- Mode, `a`, `b`, `c` are positional names. Thresholds, state words and the mode byte have no known meaning; "context" is descriptive, not a type name or a claim that it is a transaction hash.
- Token tag 4 as "unsigned integer" and the ABI shape (three 32-byte words, big-endian, 96 bytes) follow from the Uint arm and from the earlier packets' description of the encoder; the flatten step `0x169bf30` was not re-read for three tokens.
- The array writer is a known-length tuple without buffering (compound marker `0x8000000000000000`); that is the reading of `0x41d4eb0`/`0x41d2670`/`0x41d3f60`.
- The only error source of the MessagePack path is allocation failure, which ends in the `unwrap` panic at `0x38d329f`; this is not modelled.

## Reproduce

From the repository root with the authenticated artifact at `artifacts/node/115/hl-node` (a Git LFS pointer in a fresh checkout) and Python 3.12, Rust with `cargo` on `PATH`:

```sh
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
mkdir -p work
python3 research/work-items/RE-005-node115-event-context-id/gen_oracle.py --selftest
python3 research/work-items/RE-005-node115-event-context-id/gen_oracle.py --outdir work/ec-oracle
cmp work/ec-oracle/cases.tsv src/node115-event-context-id/tests/cases.tsv
python3 research/work-items/RE-005-node115-event-context-id/verify_target.py --outdir work/ec-verify
cargo test --offline --locked --target-dir work/ec-target --manifest-path src/node115-event-context-id/Cargo.toml
cargo test --release --offline --locked --target-dir work/ec-target --manifest-path src/node115-event-context-id/Cargo.toml
python3 research/work-items/RE-005-node115-event-context-id/mutate.py --selftest --outdir work/ec-mutate-self
python3 research/work-items/RE-005-node115-event-context-id/mutate.py --outdir work/ec-mutate
sha256sum -c research/work-items/RE-005-node115-event-context-id/MANIFEST.sha256
```

Each tool writes only into a directory it creates; it refuses an existing path or one inside this packet or the crate, and never modifies its inputs. `work/` is ignored by Git.

## Tests

None of the new Rust tests are collected by `make test` (`tools/run_tests.py` discovers Python tests); run the two `cargo test` commands above by hand.

- `gen_oracle.py` fixes 613 expected rows before the Rust existed (`ORACLE_FROZEN.txt`: UTC time and SHA-256 of generator and corpus). Keccak-f constants come from the FIPS 202 rules, and the sponge is checked against `hashlib.sha3_256` for ten lengths (0..300, several blocks) and five published Keccak-256 vectors; MessagePack against the format examples. What stays shared with the Rust: the mode/threshold rules, arithmetic constants and overlay rule are one reading of the node bytes, written in a different notation (half-open ranges, `bit_length`, space left in the buffer).
- Crate: 7 unit tests (published Keccak vectors, MessagePack width boundaries 127/128, 255/256, 65535/65536, u32/u64 maxima, ABI word layout, every threshold ±1, overlay zero-length and fit/skip, spot-deploy tag gate) and 3 in `tests/oracle.rs`. `function_level_corpus_matches_spec_derived_expectations` compares the Rust model of the function with 613 expected rows, including arbitrary third values that are function-level cases only (the spot-deploy site passes 0; no reachable non-zero case is shown). `spot_deploy_call_site_passes_third_value_zero` replays the rows with `c = 0` through the call-site function. `one_field_changes_and_mode_only_selects_the_branch` checks that each of `a`, `b`, `c` alone changes the result and that the mode alone changes it only when it changes the branch.
- `verify_target.py`: bytes unchanged at the pinned windows, relocation slots, and crate constants present as immediates. A one-bit flip of every window is rejected (a control of the comparison, not of the meaning). It does not decode instructions; the meaning column is a reading to check with `objdump`.
- `mutate.py`: 29 mutants of `lib.rs` (the four thresholds and their inclusivity, the mode tests, the multiplier `K` and arithmetic seed 2 only (seeds 0, 1 and 3 are not mutated), rotate, endianness, MessagePack boundaries and markers, Keccak delimiter, final bit and lane order, overlay start and fit rule, zero length, spot-deploy gate and arguments; not one mutant per constant). Build and run are separate; the baseline must pass first; a mutant that does not compile or survives, or that is caught only by an unexpected test, fails the run. Selftest: an equivalent edit survives, a type error is classified as a compile error, one-digit corruptions of the corpus's context and preimage columns fail the corpus test. `mutation.json` records a run with 29 of 29 caught by an expected test.

`ok` in a row of `mutate.py` output means the mutant's observed status matched the expected one (caught by one of the listed tests; survived for the equivalent control; compile error for the broken control). It says nothing about node behaviour.

## Limits

- Static only. No node run, no differential execution, no evidence of behavioural equivalence; the expected values test the Rust model against a Python model of the same reading of the bytes plus public standards.
- Multi-block Keccak input is not implemented (the flow's preimages are at most 96 bytes). Allocation failure, unwinding and the `0x38d329f` panic are not modelled.
- Only the Uint arm of the ABI encoder was read here; the flatten and head/tail passes rest on earlier packets. Keccak absorb/squeeze rest on `evm-keccak-ripemd-hash-115`.
- The 123 other callers, the meaning of the inputs and what the event helper does with the buffer are open. `fmt` and `clippy` were not run (not installed here); tests ran with a newer Rust than the pinned 1.95.0.
- `make verify`, `make test`, `make catalogue-check` and `make reproduce` results are in the pull request text.

## Next question

What do the state words at `+0x28` and `+0x08` and the mode byte at `+0xb9a` hold, so that the two threshold pairs (`0x0df59bc0`/`0x19067a34` for mode 2, `0x0d377be0`/`0x2a166de8` above) can be named, and can the third argument of the six callers that load it from memory be non-zero?
