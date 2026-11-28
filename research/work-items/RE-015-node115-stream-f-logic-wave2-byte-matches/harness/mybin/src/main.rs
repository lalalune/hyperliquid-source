#![forbid(unsafe_code)]
use mylib::*;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() {
    let h = AbciStateInfoHandler {
        inner: Box::new(InnerState::default()),
    };
    let s = std::hint::black_box("req");
    let c = std::hint::black_box(ReqCtxN::default());
    let cp = std::hint::black_box(ReqCtxPP::default());
    let _ = std::hint::black_box(h.w0_u64(s));
    let _ = std::hint::black_box(h.w0_r24v0(s));
    let _ = std::hint::black_box(h.w0_r32v1(s));
    let _ = std::hint::black_box(h.w0_r48v1(s));
    let _ = std::hint::black_box(h.wa_a20_e4t5(s, A20::default()));
    let _ = std::hint::black_box(h.wa_a20_r24v0(s, A20::default()));
    let _ = std::hint::black_box(h.wa_a20_r32v1(s, A20::default()));
    let _ = std::hint::black_box(h.wa_a20_p32(s, A20::default()));
    let _ = std::hint::black_box(h.wa_a20_r21t5(s, A20::default()));
    let _ = std::hint::black_box(h.wa_a20_r40e2(s, A20::default()));
    let _ = std::hint::black_box(h.wa_a20_r56e2(s, A20::default()));
    let _ = std::hint::black_box(h.wa_a20_r80e3(s, A20::default()));
    let _ = std::hint::black_box(h.wa_a20_r104e2(s, A20::default()));
    let _ = std::hint::black_box(h.wa_a20_r112t419(s, A20::default()));
    let _ = std::hint::black_box(h.wa_a20_r288e2(s, A20::default()));
    let _ = std::hint::black_box(h.wa_e21_r8n(s, E21::default()));
    let _ = std::hint::black_box(h.wa_e21_r168e2(s, E21::default()));
    let _ = std::hint::black_box(h.wa_a40_u64(s, A40::default()));
    let _ = std::hint::black_box(h.wa_bool_r48v0(s, false));
    let _ = std::hint::black_box(h.wa_bool_u8_r56e3(s, false));
    let _ = std::hint::black_box(h.wa_u64_r32v2(s, 0));
    let _ = std::hint::black_box(h.wa_u64_r96v1(s, 0));
    let _ = std::hint::black_box(h.wa_u64_r112t419(s, 0));
    let _ = std::hint::black_box(h.wa_u64b_r96v2(s, (0, false)));
    let _ = std::hint::black_box(AbciStateInfoHandler::wa_str_r112t419(String::new(), cp, &h));
    let _ = std::hint::black_box(AbciStateInfoHandler::wa_str24_r112t419(
        (String::new(), [0; 3]),
        cp,
        &h,
    ));
    let _ = std::hint::black_box(AbciStateInfoHandler::wa_str24_r128e2(
        (String::new(), [0; 3]),
        cp,
        &h,
    ));
    let _ = std::hint::black_box(AbciStateInfoHandler::wa_s64d_unit(
        S64Drop::default(),
        cp,
        &h,
    ));
    let _ = std::hint::black_box(AbciStateInfoHandler::wa_a9b_r80e2(A9B::default(), c, &h));
    let _ = std::hint::black_box(AbciStateInfoHandler::wa_a9b_r216e4(A9B::default(), c, &h));
    let _ = std::hint::black_box(AbciStateInfoHandler::wa_str8_r128u128(
        (String::new(), 0),
        cp,
        &h,
    ));
    if std::hint::black_box(false) {
        h.anti_all();
    }
}
