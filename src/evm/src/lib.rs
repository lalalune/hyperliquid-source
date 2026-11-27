#![forbid(unsafe_code)]
//! Node #115 HyperEVM execution component (`l1/src/evm/*`, `revm-precompile`).
//!
//! Target: Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

pub mod gas;
pub mod lt_hash;
pub mod precompiles;

pub use gas::{
    admit_mode13_gas, compute_mode13_gas, Mode13GasAdmission, Mode13GasBreakdown, Mode13GasInput,
};
pub use lt_hash::{EvmDbKeyspace, EvmLtHashes, LtHash, LT_HASH_BYTES, LT_HASH_LANES};
pub use node115_child_reserve_fold::{
    fold as fold_child_reserve, CallResultWords, FrameWords, SpecialStatus54,
};
pub use node115_evm_precompile_outcome_names::ReadPrecompileOutcomeName;
pub use node115_evm_tx_type_names::Node115EvmTransactionType;
pub use node115_read_precompile_result::ReadPrecompileResultKind;
pub use node115_sstore_warm::{
    execute as execute_warm_sstore, Account as WarmSstoreAccount, Fault as WarmSstoreFault,
    GasParams as WarmSstoreGasParams, Host as WarmSstoreHost,
    Interpreter as WarmSstoreInterpreter, Journal as WarmSstoreJournal, Slot as WarmSstoreSlot,
    Status as WarmSstoreStatus,
};
pub use node115_token_id::{keccak256, Keccak256};
pub use node115_transient_rollback_branches::{
    erase_controls as erase_transient_controls, restore as restore_transient_journal,
    InvalidControls as TransientInvalidControls, Journal as TransientJournal,
    Transient as TransientStorage,
};
pub use precompiles::{
    execute_l1_block_number_precompile, is_scaled_precompile_active, read_precompile_address,
    read_precompile_fixed_output_len, read_precompile_preflight_gas, read_precompile_total_gas,
    run_scaled_precompile, scaled_precompile_divisor, ReadPrecompileOutput, ScaledPrecompileError,
    READ_PRECOMPILE_BASE_GAS, READ_PRECOMPILE_GAS_PER_BYTE, READ_PRECOMPILE_MAX_INPUT_LEN,
    READ_PRECOMPILE_SUFFIXES, SCALED_PRECOMPILES,
};
