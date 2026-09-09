//! Runs only after the real Pilot hash gate and sandbox, never as init.
use std::arch::asm;
use std::ffi::{c_char, c_int, c_ulong};
unsafe extern "C" {
    fn ioperm(from: c_ulong, num: c_ulong, enable: c_int) -> c_int;
    fn iopl(level: c_int) -> c_int;
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn syscall(number: i64, ...) -> i64;
}
fn receive() -> u8 {
    let byte;
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
        // No retained capabilities, including CAP_SYS_RAWIO, after exec.
        let mut header = [0x20080522u32, 0];
        let mut caps = [u32::MAX; 6];
        assert_eq!(syscall(125, header.as_mut_ptr(), caps.as_mut_ptr()), 0);
        assert_eq!(caps, [0; 6]);
        for (start, count) in [(0x500, 3), (0x520, 4), (0x523, 1), (0x510, 1)] {
            assert_eq!(ioperm(start, count, 1), -1);
        }
        assert_eq!(iopl(3), -1);
        assert_eq!(socket(2, 1, 0), -1);
        // Attempt to recreate a raw-I/O device (mknod, /dev/port).
        assert_eq!(
            syscall(
                133,
                c"/tmp/port".as_ptr() as *const c_char,
                0o20600u32,
                0x104u64
            ),
            -1
        );
    }
    for path in ["/dev/port", "/dev/mem", "/dev/kmem"] {
        assert!(std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .is_err());
    }
    assert!(std::fs::write("/parent", b"tamper").is_err());
    let mut remembered = Vec::new();
    for turn in 1..=3 {
        let len = u32::from_le_bytes(std::array::from_fn(|_| receive())) as usize;
        assert!((1..=8192).contains(&len));
        let input: Vec<u8> = (0..len).map(|_| receive()).collect();
        if let Some(value) = input.strip_prefix(b"remember:") {
            remembered = value.to_vec();
        } else {
            assert_eq!(input, b"recall");
        }
        let response = format!("confined:{turn}:{}", String::from_utf8_lossy(&remembered));
        for byte in response.bytes() {
            send(0x521, byte);
        }
        send(0x522, 1);
    }
}
