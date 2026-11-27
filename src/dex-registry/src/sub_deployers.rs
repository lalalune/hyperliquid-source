//! HIP-3 `sub_deployers` deploy-action enum, MessagePack element writer, and
//! deployment-authorization lookup.
//!
//! Anchored to node #115 evidence packet `research/work-items/dex-registry-sub-deployers-115`
//! (`0x22927f0`, `0x2bc7610`, `0x2bc6150`, `0x2299050`, `0x2eabb50` — 12,036 cases, 0 mismatches).

use std::collections::{BTreeMap, BTreeSet};

use crate::{format_address_hex, msgpack, Address};

/// All 23 HIP-3 sub-deployer action variants observed in node #115 jump tables
/// `0x2bc7610` (outer tags 0..=22) and `0x2bc6150` (`hip3Star` sub-tags 0..=7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Hip3DeployAction {
    Hip3StarModifyApproval = 0,
    Hip3StarModifyBackstopLiquidatorApproval = 1,
    Hip3StarSetReduceOnly = 2,
    Hip3StarCancel = 3,
    Hip3StarCancelAll = 4,
    Hip3StarOrder = 5,
    Hip3StarSendAsset = 6,
    Hip3StarSetOracle = 7,
    RegisterAsset = 8,
    SetOracle = 9,
    InsertMarginTable = 10,
    SetFeeRecipient = 11,
    HaltTrading = 12,
    SetMarginTableIds = 13,
    SetOpenInterestCaps = 14,
    SetFundingMultipliers = 15,
    SetMarginModes = 16,
    SetDeployerFees = 17,
    SetFundingInterestRates = 18,
    DisableDex = 19,
    SetPerpAnnotation = 20,
    MigrateDexQuoteToken = 21,
    SetFundingClamps = 22,
}

impl Hip3DeployAction {
    /// Complete ordered list matching jump-table indices `0..=22`.
    pub const ALL: [Self; 23] = [
        Self::Hip3StarModifyApproval,
        Self::Hip3StarModifyBackstopLiquidatorApproval,
        Self::Hip3StarSetReduceOnly,
        Self::Hip3StarCancel,
        Self::Hip3StarCancelAll,
        Self::Hip3StarOrder,
        Self::Hip3StarSendAsset,
        Self::Hip3StarSetOracle,
        Self::RegisterAsset,
        Self::SetOracle,
        Self::InsertMarginTable,
        Self::SetFeeRecipient,
        Self::HaltTrading,
        Self::SetMarginTableIds,
        Self::SetOpenInterestCaps,
        Self::SetFundingMultipliers,
        Self::SetMarginModes,
        Self::SetDeployerFees,
        Self::SetFundingInterestRates,
        Self::DisableDex,
        Self::SetPerpAnnotation,
        Self::MigrateDexQuoteToken,
        Self::SetFundingClamps,
    ];

    /// Decode from the observed 1-byte enum discriminant `0..=22`.
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Hip3StarModifyApproval),
            1 => Some(Self::Hip3StarModifyBackstopLiquidatorApproval),
            2 => Some(Self::Hip3StarSetReduceOnly),
            3 => Some(Self::Hip3StarCancel),
            4 => Some(Self::Hip3StarCancelAll),
            5 => Some(Self::Hip3StarOrder),
            6 => Some(Self::Hip3StarSendAsset),
            7 => Some(Self::Hip3StarSetOracle),
            8 => Some(Self::RegisterAsset),
            9 => Some(Self::SetOracle),
            10 => Some(Self::InsertMarginTable),
            11 => Some(Self::SetFeeRecipient),
            12 => Some(Self::HaltTrading),
            13 => Some(Self::SetMarginTableIds),
            14 => Some(Self::SetOpenInterestCaps),
            15 => Some(Self::SetFundingMultipliers),
            16 => Some(Self::SetMarginModes),
            17 => Some(Self::SetDeployerFees),
            18 => Some(Self::SetFundingInterestRates),
            19 => Some(Self::DisableDex),
            20 => Some(Self::SetPerpAnnotation),
            21 => Some(Self::MigrateDexQuoteToken),
            22 => Some(Self::SetFundingClamps),
            _ => None,
        }
    }

    /// True for tags `0..=7`, encoded as the 1-entry map `{"hip3Star": name}`.
    pub const fn is_hip3_star(self) -> bool {
        (self as u8) <= 7
    }

    /// Exact variant wire string observed in `dex-registry-sub-deployers-115/name-table.tsv`.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Hip3StarModifyApproval => "modifyApproval",
            Self::Hip3StarModifyBackstopLiquidatorApproval => "modifyBackstopLiquidatorApproval",
            Self::Hip3StarSetReduceOnly => "setReduceOnly",
            Self::Hip3StarCancel => "cancel",
            Self::Hip3StarCancelAll => "cancelAll",
            Self::Hip3StarOrder => "order",
            Self::Hip3StarSendAsset => "sendAsset",
            Self::Hip3StarSetOracle => "setOracle",
            Self::RegisterAsset => "registerAsset",
            Self::SetOracle => "setOracle",
            Self::InsertMarginTable => "insertMarginTable",
            Self::SetFeeRecipient => "setFeeRecipient",
            Self::HaltTrading => "haltTrading",
            Self::SetMarginTableIds => "setMarginTableIds",
            Self::SetOpenInterestCaps => "setOpenInterestCaps",
            Self::SetFundingMultipliers => "setFundingMultipliers",
            Self::SetMarginModes => "setMarginModes",
            Self::SetDeployerFees => "setDeployerFees",
            Self::SetFundingInterestRates => "setFundingInterestRates",
            Self::DisableDex => "disableDex",
            Self::SetPerpAnnotation => "setPerpAnnotation",
            Self::MigrateDexQuoteToken => "migrateDexQuoteToken",
            Self::SetFundingClamps => "setFundingClamps",
        }
    }

    /// Encodes the action key in exact node #115 MessagePack bytes (`0x2bc7610` / `0x2bc6150`).
    pub fn encode_msgpack(self, out: &mut Vec<u8>) {
        if self.is_hip3_star() {
            out.push(0x81); // fixmap(1)
            msgpack::write_str(out, b"hip3Star");
        }
        msgpack::write_str(out, self.wire_name().as_bytes());
    }
}

/// Encodes one `[action, [address_hex, ...]]` element of `sub_deployers` (`0x22927f0`).
pub fn encode_sub_deployer_element(
    out: &mut Vec<u8>,
    action: Hip3DeployAction,
    addresses: &BTreeSet<Address>,
) {
    out.push(0x92); // fixarray(2)
    action.encode_msgpack(out);
    msgpack::write_array_len(out, addresses.len());
    for addr in addresses {
        let hex = format_address_hex(addr);
        msgpack::write_str(out, hex.as_bytes());
    }
}

/// Ordered sub-deployer permission table keyed by [`Hip3DeployAction`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubDeployers {
    pub permissions: BTreeMap<Hip3DeployAction, BTreeSet<Address>>,
}

impl SubDeployers {
    pub fn grant(&mut self, action: Hip3DeployAction, addr: Address) {
        self.permissions.entry(action).or_default().insert(addr);
    }

    pub fn revoke(&mut self, action: Hip3DeployAction, addr: &Address) -> bool {
        let mut remove_key = false;
        let removed = if let Some(set) = self.permissions.get_mut(&action) {
            let r = set.remove(addr);
            remove_key = set.is_empty();
            r
        } else {
            false
        };
        if remove_key {
            self.permissions.remove(&action);
        }
        removed
    }

    /// Returns `true` if `caller` is the main `deployer` or holds explicit
    /// sub-deployer authorization for `action`.
    pub fn is_authorized(
        &self,
        deployer: &Address,
        action: Hip3DeployAction,
        caller: &Address,
    ) -> bool {
        if caller == deployer {
            return true;
        }
        self.permissions
            .get(&action)
            .is_some_and(|set| set.contains(caller))
    }

    /// Encodes the full `sub_deployers` sequence matching `0x2ce6f90` + `0x2205280` + `0x22927f0`.
    pub fn encode_msgpack(&self, out: &mut Vec<u8>) {
        msgpack::write_array_len(out, self.permissions.len());
        for (&action, addrs) in &self.permissions {
            encode_sub_deployer_element(out, action, addrs);
        }
    }
}
