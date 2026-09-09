//! Hardware-only transport fixture, NOT an admitted Harness or production init.
//! A heap allocation lives across VM yields. The host sends the remembered
//! value only once; later messages cannot reconstruct it.
use std::arch::asm;
use std::ffi::{c_char, c_int, c_ulong, c_void};
use std::io::Write;

unsafe extern "C" {
    fn mount(
        src: *const c_char,
        dst: *const c_char,
        fs: *const c_char,
        flags: c_ulong,
        data: *const c_void,
    ) -> c_int;
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn dup2(old: c_int, new: c_int) -> c_int;
    fn ioperm(from: c_ulong, num: c_ulong, enable: c_int) -> c_int;
}

fn receive() -> u8 {
    let byte: u8;
    unsafe {
        asm!("in al, dx", out("al") byte, in("dx") 0x520u16, options(nomem, nostack));
    }
    byte
}

fn send(port: u16, byte: u8) {
    unsafe {
        asm!("out dx, al", in("al") byte, in("dx") port, options(nomem, nostack));
    }
}

fn main() {
    unsafe {
        assert_eq!(
            mount(
                c"devtmpfs".as_ptr(),
                c"/dev".as_ptr(),
                c"devtmpfs".as_ptr(),
                0,
                std::ptr::null()
            ),
            0
        );
        let console = open(c"/dev/console".as_ptr(), 2);
        assert!(console >= 0);
        assert_eq!(dup2(console, 1), 1);
        assert_eq!(dup2(console, 2), 2);
    }
    println!("CELLN:mote=parked");
    println!("CELLN:parent_fixture=parked");
    std::io::stdout().flush().unwrap();
    // The warm fork resumes here. Only this test init gets the probe ports.
    unsafe {
        assert_eq!(ioperm(0x520, 3, 1), 0);
    }
    let mut remembered = Vec::new();
    let mut turns = 0u64;
    loop {
        let size = u32::from_le_bytes(std::array::from_fn(|_| receive())) as usize;
        assert!((1..=8192).contains(&size));
        let input: Vec<u8> = (0..size).map(|_| receive()).collect();
        if input == b"busy" {
            println!("CELLN:parent_busy=entered");
            std::io::stdout().flush().unwrap();
            loop {
                std::hint::spin_loop();
            }
        }
        turns += 1;
        if let Some(value) = input.strip_prefix(b"remember:") {
            remembered = value.to_vec();
        } else {
            assert_eq!(input, b"recall");
        }
        let response = format!("{turns}:{}", String::from_utf8_lossy(&remembered));
        for byte in response.bytes() {
            send(0x521, byte);
        }
        send(0x522, 1);
    }
}
