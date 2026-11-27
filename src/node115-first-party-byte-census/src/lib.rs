#![forbid(unsafe_code)]

//! Independently authored first-party node #115 functions for compiled-byte comparison
//! with `rustc 1.95.0 (59807616e 2026-04-14)` (`-C opt-level=3 -C overflow-checks=yes`).

use std::collections::VecDeque;

/// ABI-shaped 9-variant error enum modeling the `rmp_serde::decode::Error` layout observed
/// in node #115 (`Ok(u8)` receives niche discriminant `0x09`).
#[derive(Debug, PartialEq, Eq)]
pub enum RmpErr {
    E0(u8, usize),
    E1(u8),
    E2(u8),
    E3(u8),
    E4(u8),
    E5(u8),
    E6(u8),
    E7(u8),
    E8(u8),
}

/// ABI-shaped boxed error payload modeling the `serde_json::Error` layout observed in node #115.
#[derive(Debug, PartialEq, Eq)]
pub struct JsonErr(pub Box<[usize; 2]>);

#[cold]
#[inline(never)]
fn rmp_unknown_variant(v: &str, expected: &'static [&'static str]) -> RmpErr {
    let p = core::hint::black_box((v.as_ptr(), v.len(), expected.as_ptr(), expected.len()));
    RmpErr::E0(p.0 as u8, p.1 ^ (p.2 as usize) ^ p.3)
}

#[cold]
#[inline(never)]
fn json_unknown_variant(v: &str, expected: &'static [&'static str]) -> JsonErr {
    let p = core::hint::black_box((v.as_ptr(), v.len(), expected.as_ptr(), expected.len()));
    JsonErr(Box::new([(p.0 as usize) ^ p.1, (p.2 as usize) ^ p.3]))
}

/// Keeps the cold error helpers externally reachable so argument registers are preserved.
pub fn retain_cold_error_helpers(v: &str) -> (RmpErr, JsonErr) {
    (rmp_unknown_variant(v, &[]), json_unknown_variant(v, &[]))
}

// ---------------------------------------------------------------------------
// Leaf first-party helpers (raw-equal & relocation-qualified)
// ---------------------------------------------------------------------------

/// `l1-shared`: 20-byte slice equality (`0x5436860`, 86B, raw-equal; `l1/src/raw_signature_tracker.rs`).
#[inline(never)]
pub fn fp_slice20_equal(a: &[[u8; 20]], b: &[[u8; 20]]) -> bool {
    a == b
}

/// `fees`: adjacent descending binary64 window scan (`0x36e1b10`, 113B; `l1/src/fees/`).
#[inline(never)]
pub fn fp_fee_window_scan(w: &mut core::slice::Windows<'_, f64>) -> bool {
    w.any(|pair| pair[1] > pair[0])
}

/// `assets`: in-place 256-bit unsigned subtraction with final borrow (`0x2ccdd80`, `0x43be060`, `0x564c830`, 49B, raw-equal; `l1/src/qtys/impl_wei.rs`).
#[inline(never)]
pub fn fp_sub256_borrow(out: &mut ([u64; 4], bool), lhs: &mut [u64; 4], rhs: &[u64; 4]) {
    let mut borrow = false;
    let mut i = 0;
    while i < 4 {
        let (d, b) = lhs[i].borrowing_sub(rhs[i], borrow);
        lhs[i] = d;
        borrow = b;
        i += 1;
    }
    *out = (*lhs, borrow);
}

/// `foundation`: bounded ring offset via `VecDeque::binary_search_by` (`0x45514d0`, 83B, raw-equal).
#[inline(never)]
pub fn fp_bounded_offset(d: &VecDeque<u64>) -> Result<usize, usize> {
    d.binary_search_by(|_| core::cmp::Ordering::Equal)
}

/// `foundation`: two-span 80-byte-stride ring iterator construction (`0x152e360`, 114B, raw-equal).
#[inline(never)]
pub fn fp_two_span_projection(
    d: &VecDeque<[u8; 80]>,
) -> std::collections::vec_deque::Iter<'_, [u8; 80]> {
    d.iter()
}

// ---------------------------------------------------------------------------
// Hyperliquid first-party enum wire-name `visit_str` codecs
// ---------------------------------------------------------------------------

macro_rules! def_enum_visitors {
    ($mod_name:ident, $ename:ident, [ $( ($var:ident, $str:literal, $tag:expr) ),+ $(,)? ]) => {
        pub mod $mod_name {
            use super::*;

            #[repr(u8)]
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub enum $ename {
                $( $var = $tag, )+
            }

            pub static FIELDS: &[&str] = &[ $( $str, )+ ];

            #[inline(never)]
            pub fn visit_str_rmp(v: &str) -> Result<$ename, RmpErr> {
                match v {
                    $( $str => Ok($ename::$var), )+
                    _ => Err(rmp_unknown_variant(v, FIELDS)),
                }
            }

            #[inline(never)]
            pub fn visit_str_json(v: &str) -> Result<$ename, JsonErr> {
                match v {
                    $( $str => Ok($ename::$var), )+
                    _ => Err(json_unknown_variant(v, FIELDS)),
                }
            }
        }
    };
}

def_enum_visitors!(chain_name, ChainName, [
    (Local, "Local", 0),
    (Sandbox, "Sandbox", 1),
    (Testnet, "Testnet", 2),
    (Mainnet, "Mainnet", 3),
]);

def_enum_visitors!(spot_mark, SpotMarkKind, [
    (Spot, "Spot", 0),
    (Mark, "Mark", 1),
    (ExternalPerp, "ExternalPerp", 2),
]);

def_enum_visitors!(tif, Tif, [
    (Alo, "Alo", 0),
    (Ioc, "Ioc", 1),
    (Gtc, "Gtc", 2),
    (FrontendMarket, "FrontendMarket", 3),
    (LiquidationMarket, "LiquidationMarket", 4),
]);

def_enum_visitors!(outcome_kind, OutcomeKind, [
    (StandaloneOutcome, "StandaloneOutcome", 0),
    (Question, "Question", 1),
    (QuestionOutcome, "QuestionOutcome", 2),
]);

def_enum_visitors!(margin_mode, MarginMode, [
    (Normal, "normal", 0),
    (NoCross, "noCross", 1),
    (StrictIsolated, "strictIsolated", 2),
]);

def_enum_visitors!(borrow_lend_op, Operation, [
    (Borrow, "borrow", 0),
    (Supply, "supply", 1),
    (Repay, "repay", 2),
    (Withdraw, "withdraw", 3),
]);

def_enum_visitors!(borrow_lend_field, BorrowLendField, [
    (Operation, "operation", 0),
    (Token, "token", 1),
    (Amount, "amount", 2),
]);

def_enum_visitors!(bridge_event, BridgeEvent, [
    (Deposit, "Deposit", 0),
    (InvalidatedWithdrawal, "InvalidatedWithdrawal", 1),
    (RequestedWithdrawal, "RequestedWithdrawal", 2),
    (FinalizedWithdrawal, "FinalizedWithdrawal", 3),
    (FinalizedValidatorSetUpdate, "FinalizedValidatorSetUpdate", 4),
    (RequestedValidatorSetUpdateEvent, "RequestedValidatorSetUpdateEvent", 5),
]);

def_enum_visitors!(hip3_disabled, DisabledState, [
    (Na, "Na", 0),
    (UserDisabled, "UserDisabled", 1),
    (ValidatorDisabled, "ValidatorDisabled", 2),
    (M, "m", 3),
]);

def_enum_visitors!(evm_tx_type, EvmTxType, [
    (Legacy, "Legacy", 0),
    (Eip2930, "Eip2930", 1),
    (Eip1559, "Eip1559", 2),
    (Eip4844, "Eip4844", 3),
    (Eip7702, "Eip7702", 4),
]);

def_enum_visitors!(evm_precompile_outcome, ReadPrecompileOutcomeName, [
    (Ok, "Ok", 0),
    (OutOfGas, "OutOfGas", 1),
    (Error, "Error", 2),
    (UnexpectedError, "UnexpectedError", 3),
]);

def_enum_visitors!(abstraction_kind, AbstractionKind, [
    (Perp, "Perp", 0),
    (Spot, "Spot", 1),
    (Token, "Token", 2),
    (Pdi, "Pdi", 3),
    (ActivateDexAbstraction, "ActivateDexAbstraction", 4),
    (ActivateUnifiedAccount, "ActivateUnifiedAccount", 5),
    (AllBoleTokens, "AllBoleTokens", 6),
]);

def_enum_visitors!(vote_choice, VoteChoice, [
    (Yes, "yes", 0),
    (No, "no", 1),
    (Abstain, "abstain", 2),
]);

def_enum_visitors!(proposal_cat, ProposalCategory, [
    (Accelerated, "accelerated", 0),
    (Constitutional, "constitutional", 1),
    (Ecosystem, "ecosystem", 2),
    (Electoral, "electoral", 3),
]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_helpers_match_target_semantics() {
        assert!(fp_slice20_equal(&[], &[]));
        assert!(fp_slice20_equal(&[[7u8; 20]], &[[7u8; 20]]));
        assert!(!fp_slice20_equal(&[[7u8; 20]], &[[8u8; 20]]));
        assert!(!fp_slice20_equal(&[[7u8; 20]], &[]));

        let desc = [5.0_f64, 3.0, 3.0, 1.0];
        let mut w = desc.windows(2);
        assert!(!fp_fee_window_scan(&mut w));
        let asc = [5.0_f64, 3.0, 4.0, 1.0];
        let mut w2 = asc.windows(2);
        assert!(fp_fee_window_scan(&mut w2));

        let mut lhs = [0u64, 0, 0, 0];
        let rhs = [1u64, 0, 0, 0];
        let mut out = ([0u64; 4], false);
        fp_sub256_borrow(&mut out, &mut lhs, &rhs);
        assert_eq!(out, ([u64::MAX; 4], true));
        assert_eq!(lhs, [u64::MAX; 4]);

        let empty: VecDeque<u64> = VecDeque::new();
        assert_eq!(fp_bounded_offset(&empty), Err(0));
        let mut ring = VecDeque::from([10u64, 20, 30, 40]);
        assert!(fp_bounded_offset(&ring).is_ok());
        ring.pop_front();
        ring.push_back(50);
        assert!(fp_bounded_offset(&ring).is_ok());

        let d80: VecDeque<[u8; 80]> = VecDeque::from([[1u8; 80], [2u8; 80]]);
        assert_eq!(fp_two_span_projection(&d80).count(), 2);
    }

    #[test]
    fn enum_visitors_accept_exact_variants_and_reject_unknown() {
        assert_eq!(chain_name::visit_str_rmp("Mainnet"), Ok(chain_name::ChainName::Mainnet));
        assert_eq!(chain_name::visit_str_json("Testnet"), Ok(chain_name::ChainName::Testnet));
        assert!(chain_name::visit_str_rmp("mainnet").is_err());

        assert_eq!(spot_mark::visit_str_rmp("ExternalPerp"), Ok(spot_mark::SpotMarkKind::ExternalPerp));
        assert!(spot_mark::visit_str_rmp("spot").is_err());

        assert_eq!(tif::visit_str_rmp("FrontendMarket"), Ok(tif::Tif::FrontendMarket));
        assert_eq!(tif::visit_str_json("LiquidationMarket"), Ok(tif::Tif::LiquidationMarket));
        assert!(tif::visit_str_rmp("GTC").is_err());

        assert_eq!(outcome_kind::visit_str_rmp("StandaloneOutcome"), Ok(outcome_kind::OutcomeKind::StandaloneOutcome));
        assert!(outcome_kind::visit_str_rmp("Other").is_err());

        assert_eq!(margin_mode::visit_str_rmp("strictIsolated"), Ok(margin_mode::MarginMode::StrictIsolated));
        assert!(margin_mode::visit_str_rmp("Normal").is_err());

        assert_eq!(borrow_lend_op::visit_str_rmp("withdraw"), Ok(borrow_lend_op::Operation::Withdraw));
        assert_eq!(borrow_lend_op::visit_str_json("borrow"), Ok(borrow_lend_op::Operation::Borrow));
        assert_eq!(borrow_lend_field::visit_str_rmp("amount"), Ok(borrow_lend_field::BorrowLendField::Amount));

        assert_eq!(bridge_event::visit_str_rmp("RequestedValidatorSetUpdateEvent"), Ok(bridge_event::BridgeEvent::RequestedValidatorSetUpdateEvent));
        assert_eq!(bridge_event::visit_str_json("Deposit"), Ok(bridge_event::BridgeEvent::Deposit));

        assert_eq!(hip3_disabled::visit_str_rmp("ValidatorDisabled"), Ok(hip3_disabled::DisabledState::ValidatorDisabled));
        assert_eq!(hip3_disabled::visit_str_json("m"), Ok(hip3_disabled::DisabledState::M));

        assert_eq!(evm_tx_type::visit_str_rmp("Eip7702"), Ok(evm_tx_type::EvmTxType::Eip7702));
        assert_eq!(evm_tx_type::visit_str_json("Legacy"), Ok(evm_tx_type::EvmTxType::Legacy));

        assert_eq!(evm_precompile_outcome::visit_str_rmp("OutOfGas"), Ok(evm_precompile_outcome::ReadPrecompileOutcomeName::OutOfGas));

        assert_eq!(abstraction_kind::visit_str_rmp("ActivateUnifiedAccount"), Ok(abstraction_kind::AbstractionKind::ActivateUnifiedAccount));
        assert_eq!(abstraction_kind::visit_str_json("AllBoleTokens"), Ok(abstraction_kind::AbstractionKind::AllBoleTokens));

        assert_eq!(vote_choice::visit_str_rmp("abstain"), Ok(vote_choice::VoteChoice::Abstain));
        assert_eq!(proposal_cat::visit_str_rmp("constitutional"), Ok(proposal_cat::ProposalCategory::Constitutional));
        assert_eq!(proposal_cat::visit_str_json("accelerated"), Ok(proposal_cat::ProposalCategory::Accelerated));
    }
}
