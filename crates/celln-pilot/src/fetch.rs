//! `pilot-fetch URL` — the guest-side half of the host-brokered fetch ABI.
//!
//! It has no sockets, raw I/O permission, or DNS. It sends an HTTPS URL over
//! private workspace FIFOs to a capability-less pilot broker; that broker owns
//! only the three required PIO ports, while `warden` owns validation, DNS
//! pinning, TLS and the request.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

const SCOPE_PROBE: &str = "--prove-ioperm-scope";
const REQUEST_FIFO: &str = ".celln-fetch-request";
const RESPONSE_PREFIX: &str = ".celln-fetch-response-";
const LOCK_FILE: &str = ".celln-fetch-lock";

fn exchange(request: &[u8]) -> std::io::Result<Vec<u8>> {
    let lock = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(LOCK_FILE)?;
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let response_name = format!("{RESPONSE_PREFIX}{}", std::process::id());
    let response_path = std::ffi::CString::new(response_name.as_str()).expect("numeric pid");
    unsafe { libc::unlink(response_path.as_ptr()) };
    if unsafe { libc::mkfifo(response_path.as_ptr(), 0o600) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut frame = Vec::with_capacity(response_name.len() + 1 + request.len());
    frame.extend_from_slice(response_name.as_bytes());
    frame.push(0);
    frame.extend_from_slice(request);

    let mut request_stream = OpenOptions::new().write(true).open(REQUEST_FIFO)?;
    request_stream.write_all(&(frame.len() as u32).to_le_bytes())?;
    request_stream.write_all(&frame)?;
    drop(request_stream);

    let mut response_stream = File::open(&response_name)?;
    let mut length = [0u8; 4];
    response_stream.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > 1 << 20 {
        return Err(std::io::Error::other("host sent invalid response length"));
    }
    let mut response = vec![0; length];
    response_stream.read_exact(&mut response)?;
    drop(response_stream);
    unsafe { libc::unlink(response_path.as_ptr()) };
    Ok(response)
}

fn main() {
    let Some(url) = std::env::args().nth(1) else {
        eprintln!("usage: pilot-fetch https://allowed.example/path");
        std::process::exit(2);
    };
    if url == SCOPE_PROBE {
        match exchange(url.as_bytes()) {
            Ok(report) => {
                std::io::stdout().write_all(&report).expect("writing proof");
                return;
            }
            Err(error) => {
                eprintln!("pilot-fetch: I/O permission proof failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if url.len() > 8192 || url.contains('\0') {
        eprintln!("pilot-fetch: invalid URL request");
        std::process::exit(2);
    }
    // The workload has only a pre-opened local stream. A capability-less
    // pilot broker owns the exact I/O bitmap and relays this bounded frame.
    let body = match exchange(url.as_bytes()) {
        Ok(body) => body,
        Err(error) => {
            eprintln!("pilot-fetch: {error}");
            std::process::exit(1);
        }
    };
    if body.starts_with(b"CELLN_FETCH_ERROR:") {
        eprintln!("pilot-fetch: {}", String::from_utf8_lossy(&body));
        std::process::exit(1);
    }
    std::io::stdout()
        .write_all(&body)
        .expect("writing response");
}
