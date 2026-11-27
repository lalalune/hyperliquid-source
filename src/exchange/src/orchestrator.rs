//! Top-level L1 `Exchange` state orchestrator wiring actions, DEX registry,
//! clearinghouse risk, orderbooks, fees, vaults, funding, and L1 shared state.
//!
//! Ready to link with `node115-abci` (`storage-abci`) for offline block replay.

use std::collections::BTreeMap;

use action_dispatch::router::{route_action, RouterArm};
use dex_registry::registry::{DexRegistry, Pdi};
use l1_shared::{
    agent_erase::State as AgentState,
    nonce_set::{NonceReject, NonceRing},
};
use node115_assets::{PerpAsset, PerpMeta, SpotMeta};
use node115_fees::credit::FeeLedger;
use node115_funding_rate::{rate as compute_funding_rate, Config as FundingRateConfig};
use node115_orderbook::Books;

use crate::Address;

/// Per-DEX clearinghouse state held inside [`Exchange::dex_registry`].
#[derive(Clone, Debug, Default)]
pub struct PerpDexClearinghouse {
    pub oracle_prices: Vec<i64>,
    pub funding_samples: BTreeMap<u64, Vec<f64>>,
    pub last_funding_rates: BTreeMap<u64, f64>,
}

/// Summary emitted by [`Exchange::end_block`] after funding-rate sampling & reset.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EndBlockSummary {
    pub height: u64,
    pub updated_funding_rates: usize,
}

/// Integrated node #115 L1 Exchange state container.
pub struct Exchange {
    pub height: u64,
    pub block_time_ms: u64,
    pub perp_meta: PerpMeta,
    pub spot_meta: SpotMeta,
    pub dex_registry: DexRegistry<PerpDexClearinghouse>,
    pub perp_books: Books<PerpAsset>,
    pub fee_ledger: FeeLedger,
    pub nonces: BTreeMap<Address, NonceRing>,
    pub agents: AgentState,
    pub display_names: BTreeMap<Address, String>,
    pub builder_approvals: BTreeMap<Address, BTreeMap<Address, u64>>,
    pub feature_flag_50: bool,
}

impl Default for Exchange {
    fn default() -> Self {
        Self::new()
    }
}

impl Exchange {
    pub fn new() -> Self {
        Self {
            height: 0,
            block_time_ms: 0,
            perp_meta: PerpMeta::default(),
            spot_meta: SpotMeta::default(),
            dex_registry: DexRegistry::new(),
            perp_books: Books::new(),
            fee_ledger: FeeLedger::default(),
            nonces: BTreeMap::new(),
            agents: AgentState::default(),
            display_names: BTreeMap::new(),
            builder_approvals: BTreeMap::new(),
            feature_flag_50: false,
        }
    }

    /// Block-start hook (`l1/src/exchange/begin_block.rs`).
    pub fn begin_block(&mut self, height: u64, block_time_ms: u64) {
        self.height = height;
        self.block_time_ms = block_time_ms;
    }

    /// Admits an order/action nonce for `signer` against `self.block_time_ms` (`0x4228310`).
    pub fn admit_nonce(&mut self, signer: &Address, nonce: u64) -> Result<usize, NonceReject> {
        let ring = self.nonces.entry(*signer).or_default();
        ring.admit(signer, nonce, self.block_time_ms, None)
    }

    /// Routes an action tag through node #115's central 92-arm router (`0x2bda7c0`),
    /// returning the resolved arm metadata and handler output.
    pub fn dispatch_tag<H, R>(&mut self, tag: u64, handler: H) -> Option<(&'static RouterArm, R)>
    where
        H: FnOnce(&mut Self, &'static RouterArm) -> R,
    {
        let flag = self.feature_flag_50;
        let block_time_ms = self.block_time_ms;
        let out = route_action(
            tag,
            |_| flag,
            || (block_time_ms / 1_000, ((block_time_ms % 1_000) * 1_000_000) as u32),
            |arm| handler(self, arm),
        )?;
        Some((out.arm, out.output))
    }

    /// Block-end hook (`l1/src/exchange/end_block.rs`): computes and resets sampled
    /// funding rates across all registered DEX clearinghouses using `node115-funding-rate`.
    pub fn end_block(&mut self, settle_funding: bool) -> EndBlockSummary {
        let mut updated = 0usize;
        if settle_funding {
            let empty_map = BTreeMap::new();
            let cfg = FundingRateConfig {
                baselines: &empty_map,
                correction_bounds: &empty_map,
                default_correction_bound: 0.0005,
                multipliers: &empty_map,
            };
            let count = self.dex_registry.len();
            for i in 0..count {
                if let Ok(slot) = self.dex_registry.get_mut(Pdi(i)) {
                    let keys: Vec<u64> = slot.clearinghouse.funding_samples.keys().copied().collect();
                    for key in keys {
                        if let Some(r) =
                            compute_funding_rate(key, &slot.clearinghouse.funding_samples, &cfg)
                        {
                            slot.clearinghouse.last_funding_rates.insert(key, r);
                            updated += 1;
                        }
                    }
                    slot.clearinghouse.funding_samples.clear();
                }
            }
        }
        EndBlockSummary {
            height: self.height,
            updated_funding_rates: updated,
        }
    }
}
