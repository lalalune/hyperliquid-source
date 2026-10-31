# RE-022-chacha12-guts-94

Standalone packet. `tools/chacha12_guts.py` builds `chacha12-guts.json` from node #94 bytes (Python standard library + optional `unicorn` for behavioural proof; no objdump/pyelftools).

Finding (bytes + emulation): `0x4e13780` is an SSE4x ChaCha block. ABI `(state, double_rounds, out)` = `(rdi, esi, rdx)` with 48-byte DJB state (32-byte material||counter64||nonce64) and 256-byte sequential 4-block output. The GOT-exported wrapper `0x4e14560` (slot `0x576e900`) tests flag bits loaded via `[0x576e350]`; one branch tail-jumps (`e9` @ `0x4e14db7`) to FN. A refill caller at `0x13c9ed2` passes `esi=6` (ChaCha12) and consumes `0x100` bytes. A Location string at `0x1e6959` (len 95, sha256-pinned) ends with `rand_chacha-0.3.1/src/guts.rs`; that plus the code shape is the crate link (no pinned xref from FN or the wrapper to `0x1e6959`). Behavioural proof runs the **real function bytes** under Unicorn on ChaCha20/12/8 reference vectors (ndr=10/6/4); outputs are byte-identical and the in-state counter advances by 4.

## Rerun

Emulation tests (`test_output_pin_and_expectations`,
`test_emu_tamper_expand_breaks_vector`, `test_exact_counts_emu_byte_identical`) run only when `unicorn` is importable (`unittest.skipUnless`); static pins and `--no-emu` JSON hash always run. `verify.py` under bare `python3` (no unicorn) runs static checks, reports `emu=skipped`, and exits 0 when those pass; with unicorn it matches the committed full JSON.

```
python3 -m venv .venv && .venv/bin/pip install unicorn
.venv/bin/python -I -B research/work-items/RE-022-chacha12-guts-94/verify.py
.venv/bin/python -O -B research/work-items/RE-022-chacha12-guts-94/verify.py
python3 -I -B research/work-items/RE-022-chacha12-guts-94/verify.py
python3 -O -B research/work-items/RE-022-chacha12-guts-94/verify.py
.venv/bin/python -I -B research/work-items/RE-022-chacha12-guts-94/independent_verify.py
.venv/bin/python -O -B research/work-items/RE-022-chacha12-guts-94/independent_verify.py
.venv/bin/python -B -m unittest tests.test_chacha12_guts
python3 -B -m unittest tests.test_chacha12_guts
for s in 0 7 99; do PYTHONHASHSEED=$s .venv/bin/python -B tools/chacha12_guts.py | sha256sum; done
PYTHONHASHSEED=0 .venv/bin/python -O -B tools/chacha12_guts.py | sha256sum
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/chacha12_guts.py --no-emu | sha256sum; done
```

## File hashes

See `MANIFEST.sha256` for the authoritative per-file digests (packet-relative paths; tools/tests via `../../../`).

## What this does not claim

- It does **not** claim an IETF RFC 8439 §2.3.2 (32-bit counter + 96-bit nonce) ABI; the carved function uses the DJB / `rand_chacha` 64-bit counter + 64-bit nonce layout.
- Other paths inside the wrapper (beyond the pinned flag-bit load at `[0x576e350]` and the `e9` tail to FN) are **not examined**; this packet does not assert AVX2/YMM or other sibling implementations.
- The `guts.rs` crate link rests on the Location string pin plus the code's shape; there is no pinned cross-reference from FN or the wrapper to `0x1e6959`.
- The full `StdRng` / `ThreadRng` type layout beyond the observed refill caller (`+0x120` state, `+0x158` remaining) is not reconstructed.
- Node #115 and other releases are not covered.
