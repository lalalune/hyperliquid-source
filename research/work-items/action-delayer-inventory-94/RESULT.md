# Result: node #94 action-delayer static inventory

Target SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. All addresses below are ELF virtual addresses, with exclusive FDE ends; evidence bytes and file offsets are retained in `inventory.json` and `excerpts.txt`.

## Observations

- One first-party Location-shaped relocation record matched the path prefix under the stated scan: `l1/src/action_delayer.rs:246:73`, slot `0x570d828`, path VA `0x1e4267`. The RIP LEA at `0x393023d` references the slot and is inside FDE `0x392fcc0..0x393033a`. This Location census is limited to the stated encoding and LEA patterns.
- Within that FDE, `ucomisd` at `0x392ff30` reads the eight bytes `52 b8 1e 85 eb 51 e8 3f` at `0x20a250` (binary64 `0.76`), followed by `jne` and `jnp`. `ucomisd` at `0x3930034` reads `00 00 00 00 00 00 00 40` at `0x20a358` (binary64 `2.0`), followed by `jbe`. The binary observations establish these constants and their local comparisons; their reference names are not debug symbols.
- The RIP LEA at `0x392ffe8` in the same FDE targets formatting data at `0x5a802f` with printable fragments `\nVty {min: `, `, max: ` and `}` separated by non-text bytes. The other scoped `.rodata` LEA, at `0x392ff5e`, targets binary formatting data rather than an established standalone diagnostic. No queue, full, disabled or mode string is claimed from this FDE. The candidate scan is not a complete inventory of all string references or indirect formatting data.
- The scoped FDE loads a pointer from RELATIVE relocation slot `0x5776220` at `0x392fd36` and calls that register at `0x392ff24`; the relocation addend is `0x392fab0`, the start of FDE `0x392fab0..0x392fcba`. This is a helper lead, not an edge between two Location-owned FDEs. Its range-test bytes are retained in the excerpts.

## Inferences and unresolved

The co-located `0.76` and `2.0` comparisons and Vty format fragments are consistent with the unlicensed reference's `MIN_ACTION_DELAY_SECONDS`, `ALERT_ACTION_DELAY_SECONDS` and status logic, but do not independently prove those names, full branch behavior or layout. No ownership or behavior is inferred merely from the reference's line number.

`FRONTEND_ACTION_ID_START` (`10000`), `FRONTEND_ACTION_ID_END` (`110000`), `BROADCASTER_ACTION_ID_START` (`100000000`) and `VTY_REFERENCE_NOTIONAL` (`10000.0`) remain unresolved under the requested Location-owned-FDE or clear-diagnostic binding rule. The called helper has a `100000000` comparison and an unsigned interval formed by subtracting `10000` and comparing with `100000`, which is a promising lead for `[10000, 110000)`; it is outside the sole Location-owned FDE, and its semantic ownership and complete data flow need further independent evidence. No scoped-FDE call edge is available between distinct delayer FDEs. No behavior, queue semantics, function names, full coverage, reconstruction or equivalence is claimed.

## Command exits

- `make doctor`: 0; static tooling available, exact reconstruction prerequisites missing.
- `make verify`: 0 with pinned LFS inputs present on the contribution tree.
- `make catalogue-check`: 0.
- Generator / focused unittest / packet verifier: 0. `make catalogue-check`: 0. `make test`: 0 (full offline suite).

Packet authored against hyperliquid-source `1f8c67c63ca4794c9689235471c60297f8a5c985`.
