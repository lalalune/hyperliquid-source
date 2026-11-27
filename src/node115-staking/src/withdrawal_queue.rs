//! Independently authored Rust reconstruction of node #115's CStaking
//! unstaking/withdrawal queue:
//! - `0x3c3bbd0..0x3c3bf47` (`c_staking::queue_withdrawal`)
//! - `0x36cb770..0x36cba51` (`WithdrawalQueue::enqueue`)
//! - `0x3c3b790..0x3c3b8d5` (`c_staking::drain_withdrawals`)
//!
//! Backed by `research/work-items/RE-008-node115-staking-withdrawal-queue`.

use std::collections::BTreeMap;

use crate::delegation::{StakingChain, add_secs_saturating};
use crate::jailing::{Address, JailingTime};

/// Exact native error tags emitted by `0x3c3bbd0` and `0x36cb770`.
pub const TAG_LONG_TERM_STAKING_LOCKED: u16 = 0x141; // 321
pub const TAG_INSUFFICIENT_WITHDRAW_BALANCE: u16 = 0x142; // 322
pub const TAG_TOO_MANY_CONCURRENT_WITHDRAWALS: u16 = 0x143; // 323

/// Maximum concurrent pending withdrawals per user (`cmp [rax+8], 4; ja` at `0x36cb7db`).
pub const MAX_CONCURRENT_WITHDRAWALS_PER_USER: u64 = 5;

/// Exact IEEE-754 `f64` withdrawal delay constants at `.rodata 0x450d00..0x450d10`.
pub const WITHDRAWAL_DELAY_LOCAL_MAINNET_BITS: u64 = 0x4122_7500_0000_0000; // 604,800.0 s (7 days)
pub const WITHDRAWAL_DELAY_SANDBOX_TESTNET_BITS: u64 = 0x4072_c000_0000_0000; // 300.0 s (5 minutes)

/// Withdrawal delay in seconds matching `0x36cb893..0x36cb8a6`.
pub const fn withdrawal_delay_secs(chain: StakingChain) -> u64 {
    match chain {
        StakingChain::Local | StakingChain::Mainnet => 604_800,
        StakingChain::Sandbox | StakingChain::Testnet => 300,
    }
}

/// Errors emitted by `0x3c3bbd0` and `0x36cb770`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WithdrawalQueueError {
    LongTermStakingLocked { until: JailingTime },
    InsufficientBalance,
    TooManyConcurrentWithdrawals { pending_count: u64 },
}

impl WithdrawalQueueError {
    pub const fn native_tag(self) -> u16 {
        match self {
            Self::LongTermStakingLocked { .. } => TAG_LONG_TERM_STAKING_LOCKED,
            Self::InsufficientBalance => TAG_INSUFFICIENT_WITHDRAW_BALANCE,
            Self::TooManyConcurrentWithdrawals { .. } => TAG_TOO_MANY_CONCURRENT_WITHDRAWALS,
        }
    }
}

/// Per-user pending withdrawal summary stored at `[state+0x268]`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PendingWithdrawalSummary {
    pub pending_wei: u64,
    pub pending_count: u64,
}

/// One 32-byte queued withdrawal entry (`wei: u64, user: [u8; 20]`) pushed at `0x36cb9ed..0x36cba11`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedWithdrawal {
    pub user: Address,
    pub wei: u64,
}

/// Pure-Rust model of `[state+0x228]` (user balances), `[state+0x248]` (maturity queue),
/// `[state+0x268]` (pending summaries), and per-user long-term lockup timestamps.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WithdrawalQueueState {
    pub user_balances: BTreeMap<Address, u64>,
    pub long_term_lockups: BTreeMap<Address, JailingTime>,
    pub pending_by_user: BTreeMap<Address, PendingWithdrawalSummary>,
    pub queue_by_maturity: BTreeMap<JailingTime, Vec<QueuedWithdrawal>>,
}

impl WithdrawalQueueState {
    /// Pending wei for `user` (`[state+0x268]` word 0).
    pub fn pending_wei(&self, user: &Address) -> u64 {
        self.pending_by_user
            .get(user)
            .map(|s| s.pending_wei)
            .unwrap_or(0)
    }

    /// Reconstructs `0x3c3bbd0` (`c_staking::queue_withdrawal`) -> `0x36cb770` (`WithdrawalQueue::enqueue`).
    pub fn queue_withdrawal(
        &mut self,
        chain: StakingChain,
        now: JailingTime,
        user: Address,
        amount: u64,
    ) -> Result<JailingTime, WithdrawalQueueError> {
        // 1. Long-term staking lockup guard (`0x3c3bd46..0x3c3bea6`):
        //    if active and now < until -> 0x141, else clear expired lockup.
        if let Some(&until) = self.long_term_lockups.get(&user) {
            if now < until {
                return Err(WithdrawalQueueError::LongTermStakingLocked { until });
            }
            self.long_term_lockups.remove(&user);
        }

        // 2. Concurrent withdrawal cap (<= 4 existing, i.e., max 5 -> 0x143)
        //    and checked pending_wei + amount <= liquid_balance (-> 0x142).
        let liquid = self.user_balances.get(&user).copied().unwrap_or(0);
        let summary = self.pending_by_user.get(&user).copied().unwrap_or_default();
        if summary.pending_count >= MAX_CONCURRENT_WITHDRAWALS_PER_USER {
            return Err(WithdrawalQueueError::TooManyConcurrentWithdrawals {
                pending_count: summary.pending_count,
            });
        }
        let Some(new_pending_wei) = summary.pending_wei.checked_add(amount) else {
            return Err(WithdrawalQueueError::InsufficientBalance);
        };
        if new_pending_wei > liquid {
            return Err(WithdrawalQueueError::InsufficientBalance);
        }

        // 3. Commit pending summary and push 32-byte entry at `now + delay`.
        self.pending_by_user.insert(
            user,
            PendingWithdrawalSummary {
                pending_wei: new_pending_wei,
                pending_count: summary.pending_count.saturating_add(1),
            },
        );
        let maturity = add_secs_saturating(now, withdrawal_delay_secs(chain));
        self.queue_by_maturity
            .entry(maturity)
            .or_default()
            .push(QueuedWithdrawal { user, wei: amount });
        Ok(maturity)
    }

    /// Reconstructs `0x3c3b790` (`c_staking::drain_withdrawals`):
    /// drains all buckets with `maturity <= now`, decrements `[state+0x268]`
    /// pending summaries, subtracts payouts from `[state+0x228]` user balances,
    /// and returns completed withdrawals in chronological order.
    pub fn drain_mature_withdrawals(&mut self, now: JailingTime) -> Vec<QueuedWithdrawal> {
        let mature_keys: Vec<JailingTime> = self
            .queue_by_maturity
            .range(..=now)
            .map(|(&t, _)| t)
            .collect();
        let mut completed = Vec::new();
        for key in mature_keys {
            if let Some(entries) = self.queue_by_maturity.remove(&key) {
                for entry in entries {
                    if let Some(summary) = self.pending_by_user.get_mut(&entry.user) {
                        summary.pending_wei = summary.pending_wei.saturating_sub(entry.wei);
                        summary.pending_count = summary.pending_count.saturating_sub(1);
                        if summary.pending_count == 0 && summary.pending_wei == 0 {
                            self.pending_by_user.remove(&entry.user);
                        }
                    }
                    if let Some(bal) = self.user_balances.get_mut(&entry.user) {
                        *bal = bal.saturating_sub(entry.wei);
                        if *bal == 0 {
                            self.user_balances.remove(&entry.user);
                        }
                    }
                    completed.push(entry);
                }
            }
        }
        completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        [b; 20]
    }

    fn t(days: i32, secs: u32) -> JailingTime {
        JailingTime {
            major: days,
            seconds: secs,
            nanos: 0,
        }
    }

    #[test]
    fn withdrawal_queue_enforces_lockup_cap5_balance_and_7d_drain() {
        let mut q = WithdrawalQueueState::default();
        q.user_balances.insert(addr(1), 1_000);
        q.long_term_lockups.insert(addr(1), t(50, 0));

        // Locked until day 50 -> 0x141
        assert_eq!(
            q.queue_withdrawal(StakingChain::Mainnet, t(49, 86_399), addr(1), 100),
            Err(WithdrawalQueueError::LongTermStakingLocked { until: t(50, 0) })
        );

        // At day 50 lockup expires and clears; Mainnet delay = 7 days (day 57)
        let mat = q
            .queue_withdrawal(StakingChain::Mainnet, t(50, 10), addr(1), 200)
            .unwrap();
        assert_eq!(mat, t(57, 10));
        assert!(!q.long_term_lockups.contains_key(&addr(1)));

        // Enqueue 4 more withdrawals on Testnet (300s delay) -> total 5 concurrent
        for i in 0..4u32 {
            let m = q
                .queue_withdrawal(StakingChain::Testnet, t(50, 20 + i), addr(1), 100)
                .unwrap();
            assert_eq!(m, t(50, 320 + i));
        }
        assert_eq!(q.pending_wei(&addr(1)), 600);

        // 6th concurrent withdrawal rejected with 0x143
        assert_eq!(
            q.queue_withdrawal(StakingChain::Testnet, t(50, 30), addr(1), 50),
            Err(WithdrawalQueueError::TooManyConcurrentWithdrawals { pending_count: 5 })
        );

        // Drain at day 50 + 325s completes the 4 Testnet withdrawals (400 wei), leaving 200 wei pending
        let done1 = q.drain_mature_withdrawals(t(50, 325));
        assert_eq!(done1.len(), 4);
        assert_eq!(q.user_balances[&addr(1)], 600);
        assert_eq!(q.pending_wei(&addr(1)), 200);

        // Trying to withdraw 401 more exceeds remaining liquid 600 - 200 = 400 -> 0x142
        assert_eq!(
            q.queue_withdrawal(StakingChain::Mainnet, t(51, 0), addr(1), 401),
            Err(WithdrawalQueueError::InsufficientBalance)
        );

        // Drain at day 57 + 10s completes the Mainnet withdrawal
        let done2 = q.drain_mature_withdrawals(t(57, 10));
        assert_eq!(
            done2,
            vec![QueuedWithdrawal {
                user: addr(1),
                wei: 200,
            }]
        );
        assert_eq!(q.user_balances[&addr(1)], 400);
        assert_eq!(q.pending_wei(&addr(1)), 0);
    }

    #[test]
    fn delay_bits_match_rodata_0x450d00() {
        assert_eq!(f64::from_bits(WITHDRAWAL_DELAY_LOCAL_MAINNET_BITS), 604_800.0);
        assert_eq!(f64::from_bits(WITHDRAWAL_DELAY_SANDBOX_TESTNET_BITS), 300.0);
    }
}
