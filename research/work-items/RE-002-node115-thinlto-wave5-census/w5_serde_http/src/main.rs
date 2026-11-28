use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn ex_serde_deep<T>(val: &T, s: &str, bytes: &[u8])
where
    T: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Debug,
{
    let _ = core::hint::black_box(serde_json::to_string(val));
    let _ = core::hint::black_box(serde_json::to_string_pretty(val));
    let _ = core::hint::black_box(serde_json::to_vec(val));
    let _ = core::hint::black_box(serde_json::to_vec_pretty(val));
    let _ = core::hint::black_box(serde_json::to_value(val));
    let _ = core::hint::black_box(serde_json::from_str::<T>(s));
    let _ = core::hint::black_box(serde_json::from_slice::<T>(bytes));
    let _ = core::hint::black_box(serde_json::from_reader::<_, T>(std::io::Cursor::new(bytes)));
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
        let _ = core::hint::black_box(serde_json::from_value::<T>(v));
    }
    let mut jd = serde_json::Deserializer::from_str(s);
    let _ = core::hint::black_box(serde_path_to_error::deserialize::<_, T>(&mut jd));

    // rmp-serde compact + named + struct_map + human_readable + from_read
    let _ = core::hint::black_box(rmp_serde::to_vec(val));
    let _ = core::hint::black_box(rmp_serde::to_vec_named(val));
    let mut buf = Vec::new();
    let mut ser = rmp_serde::Serializer::new(&mut buf).with_struct_map().with_human_readable();
    let _ = core::hint::black_box(val.serialize(&mut ser));
    let _ = core::hint::black_box(rmp_serde::from_slice::<T>(bytes));
    let _ = core::hint::black_box(rmp_serde::from_read::<_, T>(std::io::Cursor::new(bytes)));
    let mut rd = rmp_serde::Deserializer::from_read_ref(bytes).with_human_readable();
    let _ = core::hint::black_box(serde::Deserialize::deserialize(&mut rd) as Result<T, _>);

    // bincode 1.3.3 & 2.0.1 serde
    let _ = core::hint::black_box(bincode1::serialize(val));
    let _ = core::hint::black_box(bincode1::deserialize::<T>(bytes));
    let _ = core::hint::black_box(bincode::serde::encode_to_vec(val, bincode::config::standard()));
    let _ = core::hint::black_box(bincode::serde::decode_from_slice::<T, _>(bytes, bincode::config::standard()));
}

#[inline(never)]
fn touch_serde_all(arg: &str) {
    let b = arg.as_bytes();
    ex_serde_deep(&serde_json::Value::Null, arg, b);
    ex_serde_deep(&serde_json::Map::<String, serde_json::Value>::new(), arg, b);
    ex_serde_deep(&vec![serde_json::Value::Bool(true)], arg, b);
    ex_serde_deep(&BTreeMap::from([(arg.to_string(), serde_json::Value::Null)]), arg, b);
    ex_serde_deep(&HashMap::from([(arg.to_string(), serde_json::Value::Null)]), arg, b);
    ex_serde_deep(&BTreeMap::from([(arg.to_string(), arg.to_string())]), arg, b);
    ex_serde_deep(&BTreeMap::from([(arg.to_string(), 1u64)]), arg, b);
    ex_serde_deep(&BTreeMap::from([(1u64, arg.to_string())]), arg, b);
    ex_serde_deep(&BTreeMap::from([(1u64, 2u64)]), arg, b);
    ex_serde_deep(&BTreeMap::from([(1usize, 2u64)]), arg, b);
    ex_serde_deep(&BTreeMap::from([([1u8; 20], 1u64)]), arg, b);
    ex_serde_deep(&BTreeMap::from([([1u8; 32], 1u64)]), arg, b);
    ex_serde_deep(&HashMap::from([(arg.to_string(), arg.to_string())]), arg, b);
    ex_serde_deep(&HashMap::from([(arg.to_string(), 1u64)]), arg, b);
    ex_serde_deep(&HashMap::from([(1u64, 2u64)]), arg, b);
    ex_serde_deep(&HashMap::from([([1u8; 20], 1u64)]), arg, b);
    ex_serde_deep(&indexmap::IndexMap::from([(arg.to_string(), 1u64)]), arg, b);
    ex_serde_deep(&indexmap::IndexMap::from([(1u64, 2u64)]), arg, b);
    ex_serde_deep(&BTreeSet::from([arg.to_string()]), arg, b);
    ex_serde_deep(&BTreeSet::from([1u64]), arg, b);
    ex_serde_deep(&HashSet::from([arg.to_string()]), arg, b);
    ex_serde_deep(&vec![1u8, 2, 3], arg, b);
    ex_serde_deep(&vec![1u32, 2, 3], arg, b);
    ex_serde_deep(&vec![1u64, 2, 3], arg, b);
    ex_serde_deep(&vec![1i64, 2, 3], arg, b);
    ex_serde_deep(&vec![1.5f64, 2.5], arg, b);
    ex_serde_deep(&vec![arg.to_string()], arg, b);
    ex_serde_deep(&vec![[1u8; 20]], arg, b);
    ex_serde_deep(&vec![[1u8; 32]], arg, b);
    ex_serde_deep(&alloy_primitives::Address::ZERO, arg, b);
    ex_serde_deep(&alloy_primitives::B256::ZERO, arg, b);
    ex_serde_deep(&alloy_primitives::U256::ZERO, arg, b);
    ex_serde_deep(&alloy_primitives::Bytes::new(), arg, b);
    ex_serde_deep(&primitive_types::H160::zero(), arg, b);
    ex_serde_deep(&primitive_types::H256::zero(), arg, b);
    ex_serde_deep(&primitive_types::U256::zero(), arg, b);
    ex_serde_deep(&ruint::aliases::U256::ZERO, arg, b);
    ex_serde_deep(&rust_decimal::Decimal::ZERO, arg, b);
    ex_serde_deep(&smallvec::SmallVec::<[u64; 4]>::new(), arg, b);
    ex_serde_deep(&smallvec::SmallVec::<[u8; 32]>::new(), arg, b);
    let _ = core::hint::black_box(serde_json::from_str::<Box<serde_json::value::RawValue>>(arg));

    // Low-level rmp decode/encode primitives
    let mut cur = std::io::Cursor::new(b);
    let _ = core::hint::black_box(rmp::decode::read_marker(&mut cur));
    let _ = core::hint::black_box(rmp::decode::read_int::<u64, _>(&mut cur));
    let _ = core::hint::black_box(rmp::decode::read_str_len(&mut cur));
    let _ = core::hint::black_box(rmp::decode::read_array_len(&mut cur));
    let _ = core::hint::black_box(rmp::decode::read_map_len(&mut cur));
    let _ = core::hint::black_box(rmp::decode::read_bin_len(&mut cur));
    let mut out = Vec::new();
    let _ = rmp::encode::write_sint(&mut out, -123456789);
    let _ = rmp::encode::write_uint(&mut out, 123456789);
    let _ = rmp::encode::write_str(&mut out, arg);
    let _ = rmp::encode::write_bin(&mut out, b);
    let _ = rmp::encode::write_array_len(&mut out, 42);
    let _ = rmp::encode::write_map_len(&mut out, 42);
    let _ = core::hint::black_box(out);
}

#[inline(never)]
fn touch_axum_tower_futures_bytes(arg: &str) {
    use bytes::{Buf, BufMut, Bytes, BytesMut};
    let mut bm = BytesMut::with_capacity(256);
    bm.put_slice(arg.as_bytes());
    bm.put_u64(42);
    bm.put_u128(99);
    let mut fr = bm.freeze();
    let _ = core::hint::black_box((fr.split_to(fr.len().min(4)), fr.remaining()));
    let c = Bytes::from_static(b"abc").chain(Bytes::from_static(b"def"));
    let _ = core::hint::black_box(c.remaining());

    // axum 0.6.20 + tower 0.4.13 router, extractors, middleware, ws
    let app: axum::Router = axum::Router::new()
        .route("/info", axum::routing::post(|axum::Json(v): axum::Json<serde_json::Value>| async move { axum::Json(v) }))
        .route("/exchange", axum::routing::post(|body: Bytes| async move { body }))
        .route("/evm/:id", axum::routing::get(|axum::extract::Path(id): axum::extract::Path<String>, axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>| async move {
            format!("{id}:{}", q.len())
        }))
        .route("/ws", axum::routing::get(|ws: axum::extract::WebSocketUpgrade| async move {
            ws.on_upgrade(|mut socket| async move {
                while let Some(Ok(msg)) = socket.recv().await {
                    let _ = socket.send(msg).await;
                }
            })
        }))
        .layer(tower::ServiceBuilder::new()
            .layer(axum::error_handling::HandleErrorLayer::new(|_: tower::BoxError| async { http::StatusCode::INTERNAL_SERVER_ERROR }))
            .layer(tower::limit::ConcurrencyLimitLayer::new(64))
            .layer(tower::buffer::BufferLayer::new(128))
            .layer(tower::timeout::TimeoutLayer::new(std::time::Duration::from_secs(30))));
    let _ = core::hint::black_box(app);

    // futures-channel mpsc + oneshot + futures-util streams/sinks
    let (mut tx, mut rx) = futures_channel::mpsc::channel::<Bytes>(16);
    let _ = core::hint::black_box((tx.try_send(Bytes::from_static(b"x")), rx.try_next()));
    let (txu, mut rxu) = futures_channel::mpsc::unbounded::<String>();
    let _ = core::hint::black_box((txu.unbounded_send(arg.to_string()), rxu.try_next()));
    let (otx, mut orx) = futures_channel::oneshot::channel::<u64>();
    let _ = core::hint::black_box((otx.send(7), orx.try_recv()));
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "x".to_string());
    if arg == "__never__" {
        touch_serde_all(&arg);
        touch_axum_tower_futures_bytes(&arg);
    }
}
