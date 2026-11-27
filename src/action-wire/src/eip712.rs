//! EIP-712 user-signed action signing domain, selector tables, 38 schemas, and digest computation.
//!
//! Anchored to `research/work-items/action-wire-signing-digest-115`
//! (38 resolved user-signed actions, 2,673 cases, 0 mismatches).

use crate::{keccak256, Address};

/// Exact EIP-712 domain type string observed in `0x169e950`.
pub const EIP712_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// Exact EIP-712 domain name (`26` bytes).
pub const DOMAIN_NAME: &str = "HyperliquidSignTransaction";

/// Exact EIP-712 domain version (`1` byte).
pub const DOMAIN_VERSION: &str = "1";

/// Exact EIP-712 verifyingContract (always zero address across all 38 wrappers).
pub const VERIFYING_CONTRACT: Address = [0u8; 20];

/// Chain selector byte table (`0x648e198` / `0x458700`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChainSelector {
    Local = 0,
    Sandbox = 1,
    Testnet = 2,
    Mainnet = 3,
}

impl ChainSelector {
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Local),
            1 => Some(Self::Sandbox),
            2 => Some(Self::Testnet),
            3 => Some(Self::Mainnet),
            _ => None,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Local => "Local",
            Self::Sandbox => "Sandbox",
            Self::Testnet => "Testnet",
            Self::Mainnet => "Mainnet",
        }
    }
}

/// Governance vote choice selector table (`selectors.tsv`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VoteChoice {
    Yes = 0,
    No = 1,
    Abstain = 2,
}

impl VoteChoice {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Abstain => "abstain",
        }
    }
}

/// Governance proposal category selector table (`selectors.tsv`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProposalCategory {
    Accelerated = 0,
    Constitutional = 1,
    Ecosystem = 2,
    Electoral = 3,
}

impl ProposalCategory {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Accelerated => "accelerated",
            Self::Constitutional => "constitutional",
            Self::Ecosystem => "ecosystem",
            Self::Electoral => "electoral",
        }
    }
}

/// User abstraction selector table (`selectors.tsv`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AbstractionKind {
    Default = 0,
    Disabled = 1,
    DexAbstraction = 2,
    UnifiedAccount = 3,
    PortfolioMargin = 4,
}

impl AbstractionKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Disabled => "disabled",
            Self::DexAbstraction => "dexAbstraction",
            Self::UnifiedAccount => "unifiedAccount",
            Self::PortfolioMargin => "portfolioMargin",
        }
    }
}

/// Typed field value encoded into a 32-byte EIP-712 ABI word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eip712FieldValue<'a> {
    String(&'a str),
    Address(Address),
    Uint64(u64),
    Bool(bool),
    Bytes32([u8; 32]),
}

/// Encodes one EIP-712 field value into its 32-byte word.
pub fn encode_field_word(value: Eip712FieldValue<'_>) -> [u8; 32] {
    match value {
        Eip712FieldValue::String(s) => keccak256(s.as_bytes()),
        Eip712FieldValue::Address(addr) => {
            let mut word = [0u8; 32];
            word[12..32].copy_from_slice(&addr);
            word
        }
        Eip712FieldValue::Uint64(v) => {
            let mut word = [0u8; 32];
            word[24..32].copy_from_slice(&v.to_be_bytes());
            word
        }
        Eip712FieldValue::Bool(b) => {
            let mut word = [0u8; 32];
            word[31] = u8::from(b);
            word
        }
        Eip712FieldValue::Bytes32(b) => b,
    }
}

/// Computes `domainSeparator` for the fixed Hyperliquid EIP-712 domain (`0x169e950`).
///
/// `chain_id_be` is the big-endian 256-bit `uint256 chainId` word.
pub fn domain_separator(chain_id_be: [u8; 32]) -> [u8; 32] {
    let type_hash = keccak256(EIP712_DOMAIN_TYPE.as_bytes());
    let name_hash = keccak256(DOMAIN_NAME.as_bytes());
    let version_hash = keccak256(DOMAIN_VERSION.as_bytes());
    let contract_word = encode_field_word(Eip712FieldValue::Address(VERIFYING_CONTRACT));

    let mut buf = [0u8; 160];
    buf[0..32].copy_from_slice(&type_hash);
    buf[32..64].copy_from_slice(&name_hash);
    buf[64..96].copy_from_slice(&version_hash);
    buf[96..128].copy_from_slice(&chain_id_be);
    buf[128..160].copy_from_slice(&contract_word);
    keccak256(&buf)
}

/// Convenience helper computing [`domain_separator`] from a `u64` chain ID.
pub fn domain_separator_u64(chain_id: u64) -> [u8; 32] {
    let mut be = [0u8; 32];
    be[24..32].copy_from_slice(&chain_id.to_be_bytes());
    domain_separator(be)
}

/// Computes `structHash = keccak256(keccak256(encode_type) || word_1 || ... || word_n)`.
pub fn struct_hash(encode_type: &str, fields: &[Eip712FieldValue<'_>]) -> [u8; 32] {
    let type_hash = keccak256(encode_type.as_bytes());
    let mut preimage = Vec::with_capacity(32 * (1 + fields.len()));
    preimage.extend_from_slice(&type_hash);
    for &field in fields {
        preimage.extend_from_slice(&encode_field_word(field));
    }
    keccak256(&preimage)
}

/// Computes the final EIP-712 signing digest (`0x44e5db0`):
/// `keccak256(0x19 || 0x01 || domain_separator || struct_hash)`.
pub fn signing_digest(
    chain_id_be: [u8; 32],
    encode_type: &str,
    fields: &[Eip712FieldValue<'_>],
) -> [u8; 32] {
    let domain = domain_separator(chain_id_be);
    let st = struct_hash(encode_type, fields);
    let mut preimage = [0u8; 66];
    preimage[0] = 0x19;
    preimage[1] = 0x01;
    preimage[2..34].copy_from_slice(&domain);
    preimage[34..66].copy_from_slice(&st);
    keccak256(&preimage)
}

/// One resolved user-signed action EIP-712 schema from `action-wire-signing-digest-115/actions.tsv`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserSignedSchema {
    pub action: &'static str,
    pub is_multisig_payload: bool,
    pub wrapper_va: u64,
    pub encode_type: &'static str,
}

/// All 38 resolved user-signed EIP-712 schemas (19 base actions × single-sig / multi-sig payload).
pub const USER_SIGNED_SCHEMAS: [UserSignedSchema; 38] = [
    UserSignedSchema { action: "CWithdraw", is_multisig_payload: true, wrapper_va: 0x442f740, encode_type: "HyperliquidTransaction:CWithdraw(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,uint64 wei,uint64 nonce)" },
    UserSignedSchema { action: "SendAsset", is_multisig_payload: true, wrapper_va: 0x4430f50, encode_type: "HyperliquidTransaction:SendAsset(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,string destination,string sourceDex,string destinationDex,string token,string amount,string fromSubAccount,uint64 nonce)" },
    UserSignedSchema { action: "GovPropose", is_multisig_payload: true, wrapper_va: 0x442f3d0, encode_type: "HyperliquidTransaction:GovPropose(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,string title,string description,string category,uint64 nonce)" },
    UserSignedSchema { action: "CUserModify", is_multisig_payload: true, wrapper_va: 0x4430500, encode_type: "HyperliquidTransaction:CUserModify(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,bool extendLongTermStaking,uint64 nonce)" },
    UserSignedSchema { action: "GovVote", is_multisig_payload: false, wrapper_va: 0x4431640, encode_type: "HyperliquidTransaction:GovVote(string hyperliquidChain,bytes32 id,string choice,uint64 nonce)" },
    UserSignedSchema { action: "UsdSend", is_multisig_payload: false, wrapper_va: 0x44338b0, encode_type: "HyperliquidTransaction:UsdSend(string hyperliquidChain,string destination,string amount,uint64 time)" },
    UserSignedSchema { action: "ApproveAgent", is_multisig_payload: true, wrapper_va: 0x442f060, encode_type: "HyperliquidTransaction:ApproveAgent(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,address agentAddress,string agentName,uint64 nonce)" },
    UserSignedSchema { action: "TokenDelegate", is_multisig_payload: true, wrapper_va: 0x44312d0, encode_type: "HyperliquidTransaction:TokenDelegate(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,address validator,uint64 wei,bool isUndelegate,uint64 nonce)" },
    UserSignedSchema { action: "CDeposit", is_multisig_payload: false, wrapper_va: 0x442e980, encode_type: "HyperliquidTransaction:CDeposit(string hyperliquidChain,uint64 wei,uint64 nonce)" },
    UserSignedSchema { action: "SpotSend", is_multisig_payload: false, wrapper_va: 0x4432400, encode_type: "HyperliquidTransaction:SpotSend(string hyperliquidChain,string destination,string token,string amount,uint64 time)" },
    UserSignedSchema { action: "Withdraw", is_multisig_payload: false, wrapper_va: 0x4430870, encode_type: "HyperliquidTransaction:Withdraw(string hyperliquidChain,string destination,string amount,uint64 time)" },
    UserSignedSchema { action: "CWithdraw", is_multisig_payload: false, wrapper_va: 0x4435b50, encode_type: "HyperliquidTransaction:CWithdraw(string hyperliquidChain,uint64 wei,uint64 nonce)" },
    UserSignedSchema { action: "LinkStakingUser", is_multisig_payload: true, wrapper_va: 0x4435ec0, encode_type: "HyperliquidTransaction:LinkStakingUser(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,address user,bool isFinalize,uint64 nonce)" },
    UserSignedSchema { action: "SendAsset", is_multisig_payload: false, wrapper_va: 0x44331c0, encode_type: "HyperliquidTransaction:SendAsset(string hyperliquidChain,string destination,string sourceDex,string destinationDex,string token,string amount,string fromSubAccount,uint64 nonce)" },
    UserSignedSchema { action: "UsdClassTransfer", is_multisig_payload: true, wrapper_va: 0x4436230, encode_type: "HyperliquidTransaction:UsdClassTransfer(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,string amount,bool toPerp,uint64 nonce)" },
    UserSignedSchema { action: "ApproveBuilderFee", is_multisig_payload: true, wrapper_va: 0x44319b0, encode_type: "HyperliquidTransaction:ApproveBuilderFee(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,string maxFeeRate,address builder,uint64 nonce)" },
    UserSignedSchema { action: "GovPropose", is_multisig_payload: false, wrapper_va: 0x44357e0, encode_type: "HyperliquidTransaction:GovPropose(string hyperliquidChain,string title,string description,string category,uint64 nonce)" },
    UserSignedSchema { action: "UserDexAbstraction", is_multisig_payload: true, wrapper_va: 0x4435470, encode_type: "HyperliquidTransaction:UserDexAbstraction(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,address user,bool enabled,uint64 nonce)" },
    UserSignedSchema { action: "UserSetAbstraction", is_multisig_payload: true, wrapper_va: 0x4432770, encode_type: "HyperliquidTransaction:UserSetAbstraction(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,address user,string abstraction,uint64 nonce)" },
    UserSignedSchema { action: "UserPortfolioMargin", is_multisig_payload: true, wrapper_va: 0x4433540, encode_type: "HyperliquidTransaction:UserPortfolioMargin(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,address user,bool enabled,uint64 nonce)" },
    UserSignedSchema { action: "CUserModify", is_multisig_payload: false, wrapper_va: 0x4436910, encode_type: "HyperliquidTransaction:CUserModify(string hyperliquidChain,bool extendLongTermStaking,uint64 nonce)" },
    UserSignedSchema { action: "ApproveAgent", is_multisig_payload: false, wrapper_va: 0x442e610, encode_type: "HyperliquidTransaction:ApproveAgent(string hyperliquidChain,address agentAddress,string agentName,uint64 nonce)" },
    UserSignedSchema { action: "ConvertToMultiSigUser", is_multisig_payload: true, wrapper_va: 0x4431d20, encode_type: "HyperliquidTransaction:ConvertToMultiSigUser(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,string signers,uint64 nonce)" },
    UserSignedSchema { action: "TokenDelegate", is_multisig_payload: false, wrapper_va: 0x4434a00, encode_type: "HyperliquidTransaction:TokenDelegate(string hyperliquidChain,address validator,uint64 wei,bool isUndelegate,uint64 nonce)" },
    UserSignedSchema { action: "ConvertToMultiSigUser", is_multisig_payload: false, wrapper_va: 0x442e2a0, encode_type: "HyperliquidTransaction:ConvertToMultiSigUser(string hyperliquidChain,string signers,uint64 nonce)" },
    UserSignedSchema { action: "Withdraw", is_multisig_payload: true, wrapper_va: 0x442ecf0, encode_type: "HyperliquidTransaction:Withdraw(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,string destination,string amount,uint64 time)" },
    UserSignedSchema { action: "StakingLinkDisableTradingUser", is_multisig_payload: false, wrapper_va: 0x442fab0, encode_type: "HyperliquidTransaction:StakingLinkDisableTradingUser(string hyperliquidChain,address tradingUser,uint64 nonce)" },
    UserSignedSchema { action: "GovVote", is_multisig_payload: true, wrapper_va: 0x442fe20, encode_type: "HyperliquidTransaction:GovVote(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,bytes32 id,string choice,uint64 nonce)" },
    UserSignedSchema { action: "UsdClassTransfer", is_multisig_payload: false, wrapper_va: 0x4430190, encode_type: "HyperliquidTransaction:UsdClassTransfer(string hyperliquidChain,string amount,bool toPerp,uint64 nonce)" },
    UserSignedSchema { action: "LinkStakingUser", is_multisig_payload: false, wrapper_va: 0x4430be0, encode_type: "HyperliquidTransaction:LinkStakingUser(string hyperliquidChain,address user,bool isFinalize,uint64 nonce)" },
    UserSignedSchema { action: "UserDexAbstraction", is_multisig_payload: false, wrapper_va: 0x4432090, encode_type: "HyperliquidTransaction:UserDexAbstraction(string hyperliquidChain,address user,bool enabled,uint64 nonce)" },
    UserSignedSchema { action: "UserPortfolioMargin", is_multisig_payload: false, wrapper_va: 0x4432ae0, encode_type: "HyperliquidTransaction:UserPortfolioMargin(string hyperliquidChain,address user,bool enabled,uint64 nonce)" },
    UserSignedSchema { action: "UsdSend", is_multisig_payload: true, wrapper_va: 0x4432e50, encode_type: "HyperliquidTransaction:UsdSend(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,string destination,string amount,uint64 time)" },
    UserSignedSchema { action: "StakingLinkDisableTradingUser", is_multisig_payload: true, wrapper_va: 0x4433c20, encode_type: "HyperliquidTransaction:StakingLinkDisableTradingUser(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,address tradingUser,uint64 nonce)" },
    UserSignedSchema { action: "CDeposit", is_multisig_payload: true, wrapper_va: 0x4434320, encode_type: "HyperliquidTransaction:CDeposit(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,uint64 wei,uint64 nonce)" },
    UserSignedSchema { action: "UserSetAbstraction", is_multisig_payload: false, wrapper_va: 0x4434690, encode_type: "HyperliquidTransaction:UserSetAbstraction(string hyperliquidChain,address user,string abstraction,uint64 nonce)" },
    UserSignedSchema { action: "SpotSend", is_multisig_payload: true, wrapper_va: 0x4435100, encode_type: "HyperliquidTransaction:SpotSend(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,string destination,string token,string amount,uint64 time)" },
    UserSignedSchema { action: "ApproveBuilderFee", is_multisig_payload: false, wrapper_va: 0x44365a0, encode_type: "HyperliquidTransaction:ApproveBuilderFee(string hyperliquidChain,string maxFeeRate,address builder,uint64 nonce)" },
];

/// Looks up one of the 38 resolved user-signed schemas by action name and multisig payload mode.
pub fn find_user_signed_schema(
    action: &str,
    is_multisig_payload: bool,
) -> Option<&'static UserSignedSchema> {
    USER_SIGNED_SCHEMAS
        .iter()
        .find(|s| s.action == action && s.is_multisig_payload == is_multisig_payload)
}
