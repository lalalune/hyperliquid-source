# Sub-Account Evidence Packet (Node #94)

Static verification evidence packet for `l1/src/sub_account.rs` extracted from `artifacts/node/94/hl-node`
(SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`). Zero binary execution; offline ELF analysis only.

## Subsystem Extents
Total verified routine footprint: **11 FDEs**, **6,992 bytes**.

| Routine | Start | End | Size | SHA-256 |
|---|---|---|---|---|
| `SubAccounts::create_sub_account_with_address` | `0x36f3610` | `0x36f3c20` | 1552 B | `b29d7ae9f9ead60e3ec556691b1ee77505961c849bd97a47643c9fceec671fc8` |
| `SubAccountAddressDeriver::derive_sub_account_user` | `0x36f3c20` | `0x36f3ed0` | 688 B | `805350d89fc7286539c1d5a7739eabc12c9896dbecec8c9933dc27e3810dd06e` |
| `SubAccounts::lookup_master` | `0x36f3ed0` | `0x36f3fe0` | 272 B | `2f6656ca99969c889d100c0a93054970562610047efdfdd75bc8fb8f24ea4af6` |
| `SubAccounts::is_sub_account_user` | `0x36f3fe0` | `0x36f40d0` | 240 B | `a3e460b0212059b9eb5338d77f1dcd090517a4411632fc6907d93c3bf81d9a7a` |
| `SubAccounts::modify_sub_account_name` | `0x36f40d0` | `0x36f43c0` | 752 B | `3dee0465c560f389fcb87c3057710fbdf0a619fb2e0549429f298d585cc10ef2` |
| `SubAccounts::validate_new_name` | `0x36f43c0` | `0x36f4630` | 624 B | `5297cc093a2558a1e1f5a547190d13e7b9af1a25219c659711fe41b0114665a1` |
| `SubAccountEntry::serialize_json` | `0x36f4630` | `0x36f4970` | 832 B | `b1ec27196c2c7258b74633ffb89c4a7e788ca4887a67a75cd2d68dc9743a11b9` |
| `SubAccountEntry::serialize_msgpack` | `0x36f4970` | `0x36f4c50` | 736 B | `2aa2e768b58cc1eae94e399aebf44f28386da11da822d4f13dd09106b9916366` |
| `SubAccountEntry::serialize_visitor` | `0x36f4c50` | `0x36f4df0` | 416 B | `3175166b73d3b18b06534927755a0a66f29db8d36acc5bbfc8c7a285262d319b` |
| `SubAccountEntry::serialize_helper` | `0x36f4df0` | `0x36f4e80` | 144 B | `24203dad306ca68cdd630676d95d744d44603c427d3df5a56d0cf99e0a0dd7d9` |
| `SubAccounts::serialize_json` | `0x36f4e80` | `0x36f5160` | 736 B | `07b493799790bf68246163af3b7880a6078673aacc526cb90148b8dc7fe933b0` |

## Panic Records
- `0x56f1c38`: `/home/ubuntu/hl/code_Mainnet/l1/src/sub_account.rs:69:13` (referenced at `0x36f3bcd`)

## Key Constants & Limits
- `CREATE_SUB_ACCOUNT_DOMAIN`: `"createSubAccount"` (literal domain at `0x2035a0`)
- `MIN_CREATE_EQUITY_RAW`: `10,000,000` (`0x989680` at `0x36f3627`)
- `DISPLAY_USD_DIVISOR`: `100.0` (at `0x20a960`)
- `SUB_ACCOUNT_CAP_EQUITY_STEP_RAW`: `10,000,000_000` (magic mul `0xdbe6fecebdedd5bf >> 33` at `0x36f3734`)
- `SUB_ACCOUNT_CAP_BASE`: `10` (`0xa` at `0x36f3755`)
- `SUB_ACCOUNT_CAP_MAX_BONUS`: `40` (`0x28` at `0x36f3748`)
- `MAX_NAME_BYTES`: `16` (`0x10` at `0x36f43d1`)
- `MAX_WIRE_NAME_BYTES`: `100` (`0x64` at `0x36f390c`)

## Status Codes Ground Truth
- `SUCCESS_CODE = 390` (`0x186`)
- `ERR_TOO_MANY_SUB_ACCOUNTS = 214` (`0xd6`)
- `ERR_SUB_ACCOUNT_NAME_NOT_UNIQUE = 215` (`0xd7`)
- `ERR_DUPLICATE_SUB_ACCOUNT_USER = 216` (`0xd8`)
- `ERR_SUB_ACCOUNT_INVALID_NAME = 217` (`0xd9`)
- `ERR_SUB_ACCOUNT_TRANSFER_NOT_ALLOWED = 218` (`0xda`)
- `ERR_SUB_ACCOUNT_NOT_ALLOWED = 219` (`0xdb`)
- `ERR_SUB_ACCOUNT_NOT_REGISTERED = 220` (`0xdc`)
- `ERR_SUB_ACCOUNTS_NOT_ELIGIBLE = 221` (`0xdd`)
- `ERR_SELF_TRANSFER = 222` (`0xde`)
- `ERR_FULL_NAME_TOO_LONG = 323` (`0x143`)
