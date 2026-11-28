# RE-017: Compare computed offline #115 engine roots at H and H+1

The restored-root entry computes a digest at the saved coordinate. The deferred successor-root entry runs its source after the fixture state advances and that height qualifies for capture. This integration uses both entries in one Rust engine. It uses the sparse capture collector with state-derived Context height and round and one separately supplied auxiliary digest. The fixture compares both computed roots to independently pinned raw reference rows. [Restored root](https://github.com/lalalune/hyperliquid-source/pull/7753) · [Deferred successor root](https://github.com/lalalune/hyperliquid-source/pull/7762) · [Sparse capture](https://github.com/lalalune/hyperliquid-source/pull/7755)

The synthetic test restores H=42 at round 40 and uses a structurally decoded direct-quorum Block to derive successor round 41. The engine computes and retains both selected fixture roots under their actual heights. Its root input comes from the fixture state before and after replay. The expected raw reference rows come from an independent Python encoder and BLAKE3 implementation. Each row's own expected digest is first rechecked against its complete synthetic tree. A separate internally consistent reference with a different H+1 round leaves the H comparison passing while the successor comparison fails.

This is a bounded offline integration over a deliberately sparse synthetic state. Additional production capture slots, real checkpoint and block provenance, and actual H/H+1 state-root parity remain separate. The verifier applies the two exact independently reviewed engine changes only in temporary source, resolves their shared local-root statement with the deferred source and existing selector/history function, and compiles the existing sparse slot collector. It reads the pinned Linux x86-64 #115 ELF as data. Target SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Reproduce

From the repository root, set `packet` to this directory. Use Python with BLAKE3 1.0.11, Rust 1.95, and the exact Git source snapshots referenced in the verifier.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

The pinned case specifies `height` and four relative artifact entries with `path` and `sha256`: `checkpoint`, `wire`, `reference_h` and `reference_h_plus_one`. The checkpoint is synthetic fixture text with seven whitespace-delimited fields: height, round, persisted loader count, cadence, the two expected hardfork words, and the 64-digit auxiliary digest. The wire is a plain completed Block. Each reference supplies a complete raw export row for the fixture's selected tree. See the [actual offline run](offline-log.txt).
