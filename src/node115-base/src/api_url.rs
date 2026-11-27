//! API base URL routing anchored to node #115 `base/src/api_url.rs` (`0x154afa0..0x154b3ac`).

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ApiUrlKind {
    Mainnet,
    Testnet,
    WebSandbox,
}

impl ApiUrlKind {
    /// Base URL string matching node #115 `.rodata` fragments at `0x154afa0..0x154b3ac`.
    pub const fn base_url(self) -> &'static str {
        match self {
            ApiUrlKind::Mainnet => "https://api.hyperliquid.xyz/",
            ApiUrlKind::Testnet => "https://api.hyperliquid-testnet.xyz/",
            ApiUrlKind::WebSandbox => "http://localhost:3001/",
        }
    }

    pub fn endpoint(self, path: &str) -> String {
        let trimmed = path.strip_prefix('/').unwrap_or(path);
        format!("{}{trimmed}", self.base_url())
    }
}
