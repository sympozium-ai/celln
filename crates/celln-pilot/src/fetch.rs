//! `pilot-fetch URL` — the guest-side half of the host-brokered fetch ABI.
//!
//! It has no sockets and does no DNS. It sends an HTTPS URL over four private
//! I/O ports; `warden` owns validation, DNS pinning, TLS and the request.

use std::io::Write;

const TX: u16 = 0x500;
const CALL: u16 = 0x501;
const RX: u16 = 0x502;

#[inline]
unsafe fn out(port: u16, byte: u8) {
    std::arch::asm!("out dx, al", in("dx") port, in("al") byte, options(nomem, nostack));
}

#[inline]
unsafe fn input(port: u16) -> u8 {
    let byte: u8;
    std::arch::asm!("in al, dx", in("dx") port, out("al") byte, options(nomem, nostack));
    byte
}

fn main() {
    let Some(url) = std::env::args().nth(1) else {
        eprintln!("usage: pilot-fetch https://allowed.example/path");
        std::process::exit(2);
    };
    if url.len() > 8192 || url.contains('\0') {
        eprintln!("pilot-fetch: invalid URL request");
        std::process::exit(2);
    }
    // This capability is deliberately visible to the host VMM as I/O exits;
    // there is no guest network stack behind it.
    if unsafe { libc::iopl(3) } != 0 {
        eprintln!("pilot-fetch: broker channel unavailable");
        std::process::exit(1);
    }
    unsafe {
        for &b in url.as_bytes() {
            out(TX, b);
        }
        out(CALL, 1);
    }
    let mut len = [0u8; 4];
    for b in &mut len {
        *b = unsafe { input(RX) };
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > (1 << 20) {
        eprintln!("pilot-fetch: host sent invalid response length");
        std::process::exit(1);
    }
    let mut body = vec![0; len];
    for b in &mut body {
        *b = unsafe { input(RX) };
    }
    if body.starts_with(b"CELLN_FETCH_ERROR:") {
        eprintln!("pilot-fetch: {}", String::from_utf8_lossy(&body));
        std::process::exit(1);
    }
    std::io::stdout()
        .write_all(&body)
        .expect("writing response");
}
