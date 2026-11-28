#![forbid(unsafe_code)]
#![allow(dead_code)]

use serde::Serialize;
use std::hint::black_box;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

struct CollectStrTrigger;
impl Serialize for CollectStrTrigger {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&format_args!("x"))
    }
}

#[derive(Copy, Clone, Serialize)]
pub struct Round(pub u64);

#[derive(Serialize)]
pub enum GossipRpcRequest {
    ClientBlocks {
        start_round: Round,
        end_round: Round,
    },
    Peers,
    GossipStatus,
}

#[inline(never)]
fn pin_ser<T: Serialize, S: serde::Serializer>() {
    black_box(
        <T as Serialize>::serialize::<S> as fn(&T, S) -> Result<S::Ok, S::Error>,
    );
}

#[inline(never)]
fn exercise_ser<T: Serialize>(val: &T) {
    pin_ser::<T, &mut serde_json::Serializer<&mut Vec<u8>>>();
    pin_ser::<T, &mut serde_json::Serializer<Vec<u8>>>();
    let _ = black_box(serde_json::to_vec(val));
}

fn main() {
    let mut v1: Vec<u64> = black_box(Vec::new());
    v1.reserve(black_box(10));
    black_box(&v1);
    let mut v2: Vec<[u8; 32]> = black_box(Vec::new());
    v2.reserve(black_box(10));
    black_box(&v2);

    let _ = black_box(serde_json::to_string(&CollectStrTrigger));
    let _ = black_box(serde_json::to_string_pretty(&CollectStrTrigger));

    let req = black_box(GossipRpcRequest::ClientBlocks {
        start_round: Round(1),
        end_round: Round(2),
    });
    exercise_ser(&req);
}
