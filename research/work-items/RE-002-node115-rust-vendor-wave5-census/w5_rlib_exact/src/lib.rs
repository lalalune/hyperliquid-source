use sysinfo::SystemExt;

pub fn touch() -> usize {
    let _ = clap::App::new("x");
    let _ = rocksdb::Options::default();
    let _ = chrono::Utc::now();
    let _ = http::HeaderMap::new();
    let _ = bytes::Bytes::new();
    let _ = jsonrpsee_core::server::RpcModule::new(());
    let _ = indexmap::IndexMap::<u64, u64>::new();
    let _ = hashbrown::HashMap::<u64, u64>::new();
    let _ = hashbrown_16::HashMap::<u64, u64>::new();
    let _ = smallvec::SmallVec::<[u64; 4]>::new();
    let _ = sysinfo::System::new();
    1
}
