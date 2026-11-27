//! Build mode labels anchored to node #115 `base/src/build_mode.rs` (`0x1564870..0x1564b2b`).

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BuildMode {
    Debug,
    Release,
    RunClient,
}

impl BuildMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            BuildMode::Debug => "debug",
            BuildMode::Release => "release",
            BuildMode::RunClient => "run-client",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "debug" => Some(BuildMode::Debug),
            "release" => Some(BuildMode::Release),
            "run-client" => Some(BuildMode::RunClient),
            _ => None,
        }
    }
}
