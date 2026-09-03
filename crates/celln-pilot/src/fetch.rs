//! `pilot-fetch URL` — the guest-side half of the host-brokered fetch ABI.
//!
//! It has no sockets and does no DNS. It sends an HTTPS URL over three private
//! I/O ports; `warden` owns validation, DNS pinning, TLS and the request.

use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

const TX: u16 = 0x500;
const CALL: u16 = 0x501;
const RX: u16 = 0x502;
const PORT_COUNT: u16 = RX - TX + 1;
const FIRST_DENIED_PORT: u16 = RX + 1;
const SCOPE_PROBE: &str = "--prove-ioperm-scope";
const DENIAL_PROBE: &str = "--probe-denied-port";

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

fn grant_broker_ports() -> std::io::Result<()> {
    // ioperm changes only the thread's I/O bitmap. Unlike iopl(3), it does not
    // grant instruction-level privilege or access to the other 65,533 ports.
    let rc = unsafe { libc::ioperm(TX.into(), PORT_COUNT.into(), 1) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn prove_ioperm_scope() -> std::io::Result<()> {
    grant_broker_ports()?;

    // Exercise the actual direction of every operation in the ABI: request
    // bytes and dispatch are writes, response bytes are reads. A deliberately
    // malformed request is rejected by warden, but still yields a framed
    // response.
    unsafe {
        out(TX, b'x');
        out(CALL, 1);
        let mut len = [0u8; 4];
        for byte in &mut len {
            *byte = input(RX);
        }
        let len = u32::from_le_bytes(len);
        if len > 1 << 20 {
            return Err(std::io::Error::other(
                "host sent invalid proof response length",
            ));
        }
        for _ in 0..len {
            let _ = input(RX);
        }
    }

    // Linux turns an unprivileged IN/OUT #GP into SIGSEGV. Probe in a child so
    // the real guest observes the hardware/kernel denial and can report it.
    // I/O permission bitmaps survive exec, so the child has precisely the
    // three permissions granted above; success would prove the scope leaked.
    let status = Command::new(std::env::current_exe()?)
        .arg(DENIAL_PROBE)
        .status()?;
    if status.signal() != Some(libc::SIGSEGV) {
        return Err(std::io::Error::other(format!(
            "out-of-range port access was not denied with SIGSEGV: {status}"
        )));
    }
    println!("CELLN_FETCH_IOPERM_OK ports=0x500-0x502 denied=0x503:SIGSEGV");
    Ok(())
}

fn main() {
    let Some(url) = std::env::args().nth(1) else {
        eprintln!("usage: pilot-fetch https://allowed.example/path");
        std::process::exit(2);
    };
    if url == DENIAL_PROBE {
        unsafe { out(FIRST_DENIED_PORT, 0) };
        std::process::exit(0);
    }
    if url == SCOPE_PROBE {
        if let Err(e) = prove_ioperm_scope() {
            eprintln!("pilot-fetch: I/O permission proof failed: {e}");
            std::process::exit(1);
        }
        return;
    }
    if url.len() > 8192 || url.contains('\0') {
        eprintln!("pilot-fetch: invalid URL request");
        std::process::exit(2);
    }
    // This capability is deliberately visible to the host VMM as I/O exits;
    // there is no guest network stack behind it.
    if grant_broker_ports().is_err() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_range_is_exactly_the_ports_used_by_the_client() {
        assert_eq!((TX, CALL, RX), (0x500, 0x501, 0x502));
        assert_eq!(PORT_COUNT, 3);
        assert_eq!(FIRST_DENIED_PORT, 0x503);
    }
}
