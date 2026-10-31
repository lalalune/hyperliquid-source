# RE-021-blake2b-compress-94

Standalone packet. `tools/blake2b_compress.py` builds `blake2b-compress.json` from node #94 bytes (Python standard library + optional `unicorn` for behavioural proof; no objdump/pyelftools).

Finding (bytes + emulation): `0x4e9a8a0` is the BLAKE2b compression function F used by revm-precompile 16.0.0 (`src/blake2.rs` Location pin). ABI `(rounds, h, m, t, f)` = `(rdi, rsi, rdx, rcx, r8)`. All eight IV `movabs` immediates, the final-block `~IV[6]` `cmovne`, the rounds==0 early path, the SIGMA u64 table at `0x7c4a90`, and G-function rotates `rol 0x20/0x28/0x30/1` (eight of each) are pinned. Behavioural proof runs the **carved function bytes** under Unicorn on official EIP-152 vectors (vector 4 rounds=0, vector 5 rounds=12, plus vectors 6 and 7); outputs are byte-identical to the EIP.

HyperEVM precompile address `0x09` wiring is **statically shown**: precompile object at `0x574f0b0` carries `Address(0x09)` at `0x574f0c0` and receives `run()` wrapper `0x4e9d2a0` via `R_X86_64_RELATIVE`; the wrapper enforces input length `0xd5` (213), `bswap` big-endian rounds into `rdi`, rejects final-flag `f >= 2`, requires `gas >= rounds` (1 gas/round), then `call [0x5776f28]` (RELA → compress F).

## Rerun

```
python3 -m venv .venv && .venv/bin/pip install unicorn
Emulation tests (`test_output_pin_and_expectations`, seed full-JSON,
`test_emu_tamper_iv_breaks_vector`, `test_exact_counts_emu_byte_identical`) run only when `unicorn` is importable (`unittest.skipUnless`); static pins and `--no-emu` JSON hash always run.
.venv/bin/python -I -B research/work-items/RE-021-blake2b-compress-94/verify.py
.venv/bin/python -O -B research/work-items/RE-021-blake2b-compress-94/verify.py
.venv/bin/python -I -B research/work-items/RE-021-blake2b-compress-94/independent_verify.py
.venv/bin/python -O -B research/work-items/RE-021-blake2b-compress-94/independent_verify.py
.venv/bin/python -B -m unittest tests.test_blake2b_compress
for s in 0 7 99; do PYTHONHASHSEED=$s .venv/bin/python -B tools/blake2b_compress.py | sha256sum; done
PYTHONHASHSEED=0 .venv/bin/python -O -B tools/blake2b_compress.py | sha256sum
```

## File hashes

See `MANIFEST.sha256` for the authoritative per-file digests (packet-relative paths; tools/tests via `../../../`). JSON pin: `dc2420392ce8f7ad5f63dbc313b8ddb8095143a91a25eef1e9a2a7663ad78f92`.

## What this does not claim

- It does **not** claim that #154's inventory mention of `0x4e9a8a0` is a competing EIP-152 behavioural claim (non-claiming overlap only).
- Behavioural proof **does** emulate the real carved bytes via Unicorn (not merely an independent reference). The independent verifier additionally recomputes the same EIP-152 vectors with a portable Blake2b F as a cross-check.
- The runtime precompile *lookup* path (hash map vs linear scan that eventually loads the `0x574f0b0` object) is not separately pinned beyond the static Address+fn object and RELA; the object itself is the `0x09` dispatch table entry.
- Node #115 and other releases are not covered.
