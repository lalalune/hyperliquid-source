#![allow(clippy::too_many_lines)]
//! Wave 3 Hyperliquid first-party struct `FieldVisitor::visit_str` codecs.

use crate::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};

pub mod send_asset_cross_chain {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "token", "amount", "sourceDex", "destinationRecipient", "addressEncoding", "destinationChainId", "gasLimit", "data", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "token" => Ok(Variant::V2),
            "amount" => Ok(Variant::V3),
            "sourceDex" => Ok(Variant::V4),
            "destinationRecipient" => Ok(Variant::V5),
            "addressEncoding" => Ok(Variant::V6),
            "destinationChainId" => Ok(Variant::V7),
            "gasLimit" => Ok(Variant::V8),
            "data" => Ok(Variant::V9),
            "nonce" => Ok(Variant::V10),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "token" => Ok(Variant::V2),
            "amount" => Ok(Variant::V3),
            "sourceDex" => Ok(Variant::V4),
            "destinationRecipient" => Ok(Variant::V5),
            "addressEncoding" => Ok(Variant::V6),
            "destinationChainId" => Ok(Variant::V7),
            "gasLimit" => Ok(Variant::V8),
            "data" => Ok(Variant::V9),
            "nonce" => Ok(Variant::V10),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod send_asset_signed {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5, V6, V7, V8 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "destination", "sourceDex", "destinationDex", "token", "amount", "fromSubAccount", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "destination" => Ok(Variant::V2),
            "sourceDex" => Ok(Variant::V3),
            "destinationDex" => Ok(Variant::V4),
            "token" => Ok(Variant::V5),
            "amount" => Ok(Variant::V6),
            "fromSubAccount" => Ok(Variant::V7),
            "nonce" => Ok(Variant::V8),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "destination" => Ok(Variant::V2),
            "sourceDex" => Ok(Variant::V3),
            "destinationDex" => Ok(Variant::V4),
            "token" => Ok(Variant::V5),
            "amount" => Ok(Variant::V6),
            "fromSubAccount" => Ok(Variant::V7),
            "nonce" => Ok(Variant::V8),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod send_asset_wire {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5, V6 }
    pub static VARIANTS: &[&str] = &["destination", "sourceDex", "destinationDex", "token", "amount", "fromSubAccount", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "destination" => Ok(Variant::V0),
            "sourceDex" => Ok(Variant::V1),
            "destinationDex" => Ok(Variant::V2),
            "token" => Ok(Variant::V3),
            "amount" => Ok(Variant::V4),
            "fromSubAccount" => Ok(Variant::V5),
            "nonce" => Ok(Variant::V6),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "destination" => Ok(Variant::V0),
            "sourceDex" => Ok(Variant::V1),
            "destinationDex" => Ok(Variant::V2),
            "token" => Ok(Variant::V3),
            "amount" => Ok(Variant::V4),
            "fromSubAccount" => Ok(Variant::V5),
            "nonce" => Ok(Variant::V6),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod validator_change_profile {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5, V6 }
    pub static VARIANTS: &[&str] = &["node_ip", "name", "description", "unjailed", "disable_delegations", "commission_bps", "signer"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "node_ip" => Ok(Variant::V0),
            "name" => Ok(Variant::V1),
            "description" => Ok(Variant::V2),
            "unjailed" => Ok(Variant::V3),
            "disable_delegations" => Ok(Variant::V4),
            "commission_bps" => Ok(Variant::V5),
            "signer" => Ok(Variant::V6),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "node_ip" => Ok(Variant::V0),
            "name" => Ok(Variant::V1),
            "description" => Ok(Variant::V2),
            "unjailed" => Ok(Variant::V3),
            "disable_delegations" => Ok(Variant::V4),
            "commission_bps" => Ok(Variant::V5),
            "signer" => Ok(Variant::V6),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod send_asset_internal {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5 }
    pub static VARIANTS: &[&str] = &["destination", "fromSubAccount", "sourceDexOrSpot", "destinationDexOrSpot", "token", "wei"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "destination" => Ok(Variant::V0),
            "fromSubAccount" => Ok(Variant::V1),
            "sourceDexOrSpot" => Ok(Variant::V2),
            "destinationDexOrSpot" => Ok(Variant::V3),
            "token" => Ok(Variant::V4),
            "wei" => Ok(Variant::V5),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "destination" => Ok(Variant::V0),
            "fromSubAccount" => Ok(Variant::V1),
            "sourceDexOrSpot" => Ok(Variant::V2),
            "destinationDexOrSpot" => Ok(Variant::V3),
            "token" => Ok(Variant::V4),
            "wei" => Ok(Variant::V5),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod treasury_staker_cfg {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["token", "technicalStaker", "treasuryStaker", "treasuryEvmAddress", "evmRebalanceContract"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "token" => Ok(Variant::V0),
            "technicalStaker" => Ok(Variant::V1),
            "treasuryStaker" => Ok(Variant::V2),
            "treasuryEvmAddress" => Ok(Variant::V3),
            "evmRebalanceContract" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "token" => Ok(Variant::V0),
            "technicalStaker" => Ok(Variant::V1),
            "treasuryStaker" => Ok(Variant::V2),
            "treasuryEvmAddress" => Ok(Variant::V3),
            "evmRebalanceContract" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod token_delegate_action {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "validator", "wei", "isUndelegate", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "validator" => Ok(Variant::V2),
            "wei" => Ok(Variant::V3),
            "isUndelegate" => Ok(Variant::V4),
            "nonce" => Ok(Variant::V5),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "validator" => Ok(Variant::V2),
            "wei" => Ok(Variant::V3),
            "isUndelegate" => Ok(Variant::V4),
            "nonce" => Ok(Variant::V5),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod trailing_stop_order {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5 }
    pub static VARIANTS: &[&str] = &["asset", "isBuy", "sz", "reduceOnly", "retracement", "activationPx"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "asset" => Ok(Variant::V0),
            "isBuy" => Ok(Variant::V1),
            "sz" => Ok(Variant::V2),
            "reduceOnly" => Ok(Variant::V3),
            "retracement" => Ok(Variant::V4),
            "activationPx" => Ok(Variant::V5),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "asset" => Ok(Variant::V0),
            "isBuy" => Ok(Variant::V1),
            "sz" => Ok(Variant::V2),
            "reduceOnly" => Ok(Variant::V3),
            "retracement" => Ok(Variant::V4),
            "activationPx" => Ok(Variant::V5),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod gov_propose_action {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "title", "description", "category", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "title" => Ok(Variant::V2),
            "description" => Ok(Variant::V3),
            "category" => Ok(Variant::V4),
            "nonce" => Ok(Variant::V5),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "title" => Ok(Variant::V2),
            "description" => Ok(Variant::V3),
            "category" => Ok(Variant::V4),
            "nonce" => Ok(Variant::V5),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod spot_send_action {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "destination", "token", "amount", "time"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "destination" => Ok(Variant::V2),
            "token" => Ok(Variant::V3),
            "amount" => Ok(Variant::V4),
            "time" => Ok(Variant::V5),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "destination" => Ok(Variant::V2),
            "token" => Ok(Variant::V3),
            "amount" => Ok(Variant::V4),
            "time" => Ok(Variant::V5),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod validator_cold_user {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["validator", "signature", "coldUser", "coldUserSignature", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "validator" => Ok(Variant::V0),
            "signature" => Ok(Variant::V1),
            "coldUser" => Ok(Variant::V2),
            "coldUserSignature" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "validator" => Ok(Variant::V0),
            "signature" => Ok(Variant::V1),
            "coldUser" => Ok(Variant::V2),
            "coldUserSignature" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod base_fee_rates {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3 }
    pub static VARIANTS: &[&str] = &["perpAddBaseRate", "perpCrossBaseRate", "spotAddBaseRate", "spotCrossBaseRate"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "perpAddBaseRate" => Ok(Variant::V0),
            "perpCrossBaseRate" => Ok(Variant::V1),
            "spotAddBaseRate" => Ok(Variant::V2),
            "spotCrossBaseRate" => Ok(Variant::V3),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "perpAddBaseRate" => Ok(Variant::V0),
            "perpCrossBaseRate" => Ok(Variant::V1),
            "spotAddBaseRate" => Ok(Variant::V2),
            "spotCrossBaseRate" => Ok(Variant::V3),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod create_vault_action {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["name", "description", "initialUsd", "nonce", "maxUsdcFee"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "name" => Ok(Variant::V0),
            "description" => Ok(Variant::V1),
            "initialUsd" => Ok(Variant::V2),
            "nonce" => Ok(Variant::V3),
            "maxUsdcFee" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "name" => Ok(Variant::V0),
            "description" => Ok(Variant::V1),
            "initialUsd" => Ok(Variant::V2),
            "nonce" => Ok(Variant::V3),
            "maxUsdcFee" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod approve_agent_action {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "agentAddress", "agentName", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "agentAddress" => Ok(Variant::V2),
            "agentName" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "agentAddress" => Ok(Variant::V2),
            "agentName" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod register_perp_asset2 {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["coin", "szDecimals", "oraclePx", "marginTableId", "marginMode"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "coin" => Ok(Variant::V0),
            "szDecimals" => Ok(Variant::V1),
            "oraclePx" => Ok(Variant::V2),
            "marginTableId" => Ok(Variant::V3),
            "marginMode" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "coin" => Ok(Variant::V0),
            "szDecimals" => Ok(Variant::V1),
            "oraclePx" => Ok(Variant::V2),
            "marginTableId" => Ok(Variant::V3),
            "marginMode" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod approve_builder_fee {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "maxFeeRate", "builder", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "maxFeeRate" => Ok(Variant::V2),
            "builder" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "maxFeeRate" => Ok(Variant::V2),
            "builder" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod register_perp_asset {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["coin", "szDecimals", "oraclePx", "marginTableId", "onlyIsolated"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "coin" => Ok(Variant::V0),
            "szDecimals" => Ok(Variant::V1),
            "oraclePx" => Ok(Variant::V2),
            "marginTableId" => Ok(Variant::V3),
            "onlyIsolated" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "coin" => Ok(Variant::V0),
            "szDecimals" => Ok(Variant::V1),
            "oraclePx" => Ok(Variant::V2),
            "marginTableId" => Ok(Variant::V3),
            "onlyIsolated" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod usd_send_action {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "destination", "amount", "time"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "destination" => Ok(Variant::V2),
            "amount" => Ok(Variant::V3),
            "time" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "destination" => Ok(Variant::V2),
            "amount" => Ok(Variant::V3),
            "time" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod user_set_abstraction {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "user", "abstraction", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "user" => Ok(Variant::V2),
            "abstraction" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "user" => Ok(Variant::V2),
            "abstraction" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod bridge_withdrawal_req {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["user", "destination", "usd", "nonce", "signature"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "user" => Ok(Variant::V0),
            "destination" => Ok(Variant::V1),
            "usd" => Ok(Variant::V2),
            "nonce" => Ok(Variant::V3),
            "signature" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "user" => Ok(Variant::V0),
            "destination" => Ok(Variant::V1),
            "usd" => Ok(Variant::V2),
            "nonce" => Ok(Variant::V3),
            "signature" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod bridge_deposit_req {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["user", "destination", "nonce", "usd", "ethTxHash"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "user" => Ok(Variant::V0),
            "destination" => Ok(Variant::V1),
            "nonce" => Ok(Variant::V2),
            "usd" => Ok(Variant::V3),
            "ethTxHash" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "user" => Ok(Variant::V0),
            "destination" => Ok(Variant::V1),
            "nonce" => Ok(Variant::V2),
            "usd" => Ok(Variant::V3),
            "ethTxHash" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod link_staking_user {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "user", "isFinalize", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "user" => Ok(Variant::V2),
            "isFinalize" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "user" => Ok(Variant::V2),
            "isFinalize" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod portfolio_margin_limits {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4, V5, V6 }
    pub static VARIANTS: &[&str] = &["pmdl", "pmln", "pmbm", "ubgln", "ubglm", "ubuln", "ubulm"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "pmdl" => Ok(Variant::V0),
            "pmln" => Ok(Variant::V1),
            "pmbm" => Ok(Variant::V2),
            "ubgln" => Ok(Variant::V3),
            "ubglm" => Ok(Variant::V4),
            "ubuln" => Ok(Variant::V5),
            "ubulm" => Ok(Variant::V6),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "pmdl" => Ok(Variant::V0),
            "pmln" => Ok(Variant::V1),
            "pmbm" => Ok(Variant::V2),
            "ubgln" => Ok(Variant::V3),
            "ubglm" => Ok(Variant::V4),
            "ubuln" => Ok(Variant::V5),
            "ubulm" => Ok(Variant::V6),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod c_deposit_action {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "wei", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "wei" => Ok(Variant::V2),
            "nonce" => Ok(Variant::V3),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "wei" => Ok(Variant::V2),
            "nonce" => Ok(Variant::V3),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod gov_vote_action {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "id", "choice", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "id" => Ok(Variant::V2),
            "choice" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "id" => Ok(Variant::V2),
            "choice" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod user_dex_abstraction {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "user", "enabled", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "user" => Ok(Variant::V2),
            "enabled" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "user" => Ok(Variant::V2),
            "enabled" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod usd_class_transfer {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3, V4 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "amount", "toPerp", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "amount" => Ok(Variant::V2),
            "toPerp" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "amount" => Ok(Variant::V2),
            "toPerp" => Ok(Variant::V3),
            "nonce" => Ok(Variant::V4),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod subaccount_spot_transfer {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3 }
    pub static VARIANTS: &[&str] = &["subAccountUser", "isDeposit", "token", "amount"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "subAccountUser" => Ok(Variant::V0),
            "isDeposit" => Ok(Variant::V1),
            "token" => Ok(Variant::V2),
            "amount" => Ok(Variant::V3),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "subAccountUser" => Ok(Variant::V0),
            "isDeposit" => Ok(Variant::V1),
            "token" => Ok(Variant::V2),
            "amount" => Ok(Variant::V3),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod set_oracle_action {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3 }
    pub static VARIANTS: &[&str] = &["pxs", "externalPerpPxs", "usdtUsdcPx", "nativePx"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "pxs" => Ok(Variant::V0),
            "externalPerpPxs" => Ok(Variant::V1),
            "usdtUsdcPx" => Ok(Variant::V2),
            "nativePx" => Ok(Variant::V3),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "pxs" => Ok(Variant::V0),
            "externalPerpPxs" => Ok(Variant::V1),
            "usdtUsdcPx" => Ok(Variant::V2),
            "nativePx" => Ok(Variant::V3),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod long_term_staking_action {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "extendLongTermStaking", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "extendLongTermStaking" => Ok(Variant::V2),
            "nonce" => Ok(Variant::V3),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "extendLongTermStaking" => Ok(Variant::V2),
            "nonce" => Ok(Variant::V3),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod link_trading_user {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "tradingUser", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "tradingUser" => Ok(Variant::V2),
            "nonce" => Ok(Variant::V3),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "tradingUser" => Ok(Variant::V2),
            "nonce" => Ok(Variant::V3),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod convert_multisig_user {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2, V3 }
    pub static VARIANTS: &[&str] = &["signatureChainId", "hyperliquidChain", "signers", "nonce"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "signers" => Ok(Variant::V2),
            "nonce" => Ok(Variant::V3),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "signatureChainId" => Ok(Variant::V0),
            "hyperliquidChain" => Ok(Variant::V1),
            "signers" => Ok(Variant::V2),
            "nonce" => Ok(Variant::V3),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}

pub mod c_validator_register {
    use super::{json_unknown_variant, rmp_unknown_variant, JsonErr, RmpErr};
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Variant { V0, V1, V2 }
    pub static VARIANTS: &[&str] = &["profile", "unjailed", "initial_wei"];
    #[inline(never)]
    pub fn visit_str_rmp(v: &str) -> Result<Variant, RmpErr> {
        match v {
            "profile" => Ok(Variant::V0),
            "unjailed" => Ok(Variant::V1),
            "initial_wei" => Ok(Variant::V2),
            _ => Err(rmp_unknown_variant(v, VARIANTS)),
        }
    }
    #[inline(never)]
    pub fn visit_str_json(v: &str) -> Result<Variant, JsonErr> {
        match v {
            "profile" => Ok(Variant::V0),
            "unjailed" => Ok(Variant::V1),
            "initial_wei" => Ok(Variant::V2),
            _ => Err(json_unknown_variant(v, VARIANTS)),
        }
    }
}
