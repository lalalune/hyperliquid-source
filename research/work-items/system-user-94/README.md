# System User Evidence Packet (Node #94)

Static verification evidence packet for `l1/src/system_user.rs` extracted from `artifacts/node/94/hl-node`
(SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`). Zero binary execution; offline ELF analysis only.

## Subsystem Extents
Total verified routine footprint: **3 FDEs**, **8,110 bytes**.

| Routine | Start | End | Size | SHA-256 |
|---|---|---|---|---|
| `SystemUserIndexIter::next_index_with_offset` | `0x3b9d9b0` | `0x3b9d9f7` | 71 B | `1b77785b7ec902c12d4792412e3e3d0302844e66d94a947905be97b539ae3d64` |
| `SystemUserPrivilegeCheck::dispatch` | `0x3705690` | `0x37067a9` | 4377 B | `9422fe7f01d5d3470a0435c27ea11b343f2377d3037ece3e9ed0de9a0f6ec6e7` |
| `SystemUserState::init_system_users` | `0x3270830` | `0x327167e` | 3662 B | `80fab9d404ea8a1c304d44d85ba1bf86f6e5fd3b1782768529cd43b5ea677ecd` |

## Panic Records
- `0x5712ff0`: `/home/ubuntu/hl/code_Mainnet/l1/src/system_user.rs:3:23` (referenced at `0x3b9d9ea`)

## Privileged System User Table
- Extent: `0x3e35c8..0x3e37a4` (20 entries, non-numeric order: `0x0800`, `0x0813`, `0x0801..=0x0812`)
- Bitmask dispatch: `0x40006000` (bits 13, 14, 30)

## Constants & Limits
- `NUM_SYSTEM_USERS`: `30` (`0x1e`)
- `SYSTEM_USER_END_SENTINEL`: `30` (`0x1e`)
- `FIRST_PRIVILEGED_SYSTEM_USER_INDEX`: `7`
- `PRIVILEGED_SYSTEM_USER_COUNT`: `20`
- `LAST_PRIVILEGED_SYSTEM_USER_INDEX`: `26`
