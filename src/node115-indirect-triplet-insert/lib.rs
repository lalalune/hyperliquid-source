#![no_std]
#![forbid(unsafe_code)]
//! Stable complete-record relation; original pointers/API and nativeRAX unclaimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub payload: u64,
    pub key: usize,
}
/// Own adapter coordinate for the original entry-guard UD2, not native recovery.
#[derive(Debug, PartialEq, Eq)]
pub struct Guard;
fn order(key: [u32; 3]) -> (i32, u32, u32) {
    (key[0] as i32, key[1], key[2])
}
/// Insert the suffix beginning at k into the preceding prefix. Equal-key
/// records stay stable; an initially unsorted prefix need not become sorted.
/// Key coordinates must reference immutable triples. Out-of-domain key memory
/// and original fault/unwind behavior are not part of this owned safe API.
pub fn insert(records: &mut [Record], keys: &[[u32; 3]], k: u64) -> Result<(), Guard> {
    if k == 0 || k > records.len() as u64 {
        return Err(Guard);
    }
    if k == records.len() as u64 {
        return Ok(());
    }
    assert!(
        records.iter().all(|r| r.key < keys.len()),
        "qualified key coordinates"
    );
    for i in k as usize..records.len() {
        let mut at = i;
        while at > 0 && order(keys[records[at].key]) < order(keys[records[at - 1].key]) {
            records.swap(at, at - 1);
            at -= 1;
        }
    }
    Ok(())
}
