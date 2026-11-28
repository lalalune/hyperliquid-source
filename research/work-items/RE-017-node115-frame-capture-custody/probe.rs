use node115_replay_completed_payload::{
    CompletedPayload, REPLAY_LIMIT, ReplayPayload, decode_completed_payload,
};
use node115_tcp_stream_frame_lz4::{Limits, read_frame};
use std::{env, fs, io, path::Path};

fn main() -> io::Result<()> {
    let mut args = env::args_os().skip(1);
    let capture = fs::read(args.next().expect("pinned capture input"))?;
    let folder = args.next().expect("derived payload directory");
    let mut input = capture.as_slice();
    let limits = Limits {
        frame_payload: REPLAY_LIMIT,
        decoded_capacity: REPLAY_LIMIT,
    };
    for index in 0.. {
        let offset = capture.len() - input.len();
        let Some(frame) = read_frame(&mut input, limits).expect("complete offline frame") else {
            break;
        };
        let prefix = decode_completed_payload(CompletedPayload::Plain(&frame.payload)).unwrap();
        assert_eq!(
            prefix.consumed,
            frame.payload.len(),
            "one complete Block per frame"
        );
        assert!(
            matches!(prefix.result, Ok(ReplayPayload::Block { .. })),
            "expected retained Block"
        );
        let frame_size = capture.len() - input.len() - offset;
        fs::write(
            Path::new(&folder).join(format!("payload-{index}.bin")),
            &frame.payload,
        )?;
        println!(
            "{{\"index\":{index},\"offset\":{offset},\"frame_size\":{frame_size},\"payload_size\":{},\"compressed\":{}}}",
            frame.payload.len(),
            frame.was_compressed,
        );
    }
    Ok(())
}
