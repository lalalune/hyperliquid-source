#![forbid(unsafe_code)]
//! Node #115 `global_constants` crate reconstruction.
//!
//! Target: Linux x86-64 node #115
//! (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

pub mod aws_name;
pub mod static_config;

pub use aws_name::{AwsName, AwsNameFileError, VariantNotFound};
pub use node115_chain_name_codec::ChainName;
pub use node115_spot_mark_codec::SpotMarkKind;
pub use static_config::{
    aws_name_path_for_cham_dir, code_dir_for_cham_dir, home_dir, parse_static_config_json,
    read_aws_name, resolve_cham_dir, static_config_file_path, StaticConfig,
    StaticConfigParseError, JSON_WHITESPACE_MASK, STATIC_CONFIG,
};

/// Display wrapper matching `Chain::fmt` at node #115 VA `0x1778c60..0x1778cca`
/// (4-entry jump table at `0x4820f4` writing `"Local"`, `"Sandbox"`, `"Testnet"`, `"Mainnet"`).
pub struct ChainDisplay(pub ChainName);

impl core::fmt::Display for ChainDisplay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.pad(self.0.name())
    }
}
