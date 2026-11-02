use node94_five_word_combine::{apply_image, Registers};
use std::{
    env, fs,
    io::{self, Write},
    process,
};

fn run() -> Result<(), String> {
    let path = env::args().nth(1).ok_or("expected input path")?;
    let input = fs::read(path).map_err(|e| e.to_string())?;
    if input.len() % 168 != 0 {
        return Err("expected complete 168-byte input records".into());
    }
    let mut output = Vec::with_capacity(input.len() / 168 * 240);
    for row in input.chunks_exact(168) {
        let mut fields = [0_u64; 5];
        for (field, bytes) in fields.iter_mut().zip(row[..40].chunks_exact(8)) {
            *field = u64::from_le_bytes(bytes.try_into().map_err(|_| "field width")?);
        }
        if fields[4] > 128 {
            return Err("image length exceeds 128".into());
        }
        let mut image = [0_u8; 128];
        image.copy_from_slice(&row[40..]);
        let result = apply_image(
            &mut image[..fields[4] as usize],
            fields[2],
            fields[3],
            fields[0],
            fields[1],
        );
        let status = u64::from(result.is_some());
        let Registers {
            rax,
            rdx,
            rbx,
            rcx,
            rbp,
            r8,
            r9,
            r10,
            r11,
            r12,
            r13,
            r14,
            r15,
        } = result.unwrap_or(Registers {
            rax: 0,
            rdx: 0,
            rbx: 0,
            rcx: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        });
        for value in [
            status, rax, rdx, rbx, rcx, rbp, r8, r9, r10, r11, r12, r13, r14, r15,
        ] {
            output.extend_from_slice(&value.to_le_bytes());
        }
        output.extend_from_slice(&image);
    }
    io::stdout().write_all(&output).map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(2);
    }
}
