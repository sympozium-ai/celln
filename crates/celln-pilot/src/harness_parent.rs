//! Native parent adapter. Pilot must grant the mailbox before exec; this
//! process never acquires capabilities or opens a network connection.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run() -> anyhow::Result<()> {
    use std::arch::asm;
    fn read() -> u8 {
        let byte;
        unsafe {
            asm!("in al, dx", out("al") byte, in("dx") 0x520u16, options(nomem, nostack));
        }
        byte
    }
    fn write(port: u16, byte: u8) {
        unsafe {
            asm!("out dx, al", in("al") byte, in("dx") port, options(nomem, nostack));
        }
    }
    fn word() -> u16 {
        let value;
        unsafe {
            asm!("in ax, dx", out("ax") value, in("dx") 0x520u16, options(nomem, nostack));
        }
        value
    }
    let mut context = pilot::parent_harness::ParentContext::default();
    loop {
        // Empty RX reads are 0xff. Poll the low 16 bits atomically so host
        // delivery after startup acknowledgement cannot split an idle read
        // across a frame boundary. Valid frames are <=8192 bytes. A 32-bit
        // IN would need permission for 0x523, outside the three-port grant.
        let low = loop {
            let value = word();
            if value != u16::MAX {
                break value;
            }
        };
        let len = (u32::from(low) | (u32::from(word()) << 16)) as usize;
        anyhow::ensure!(
            (1..=warden::parent_mailbox::MAX_FRAME_BYTES).contains(&len),
            "invalid mailbox frame"
        );
        let input: Vec<u8> = (0..len).map(|_| read()).collect();
        let reply = context.exchange(&input).map_err(anyhow::Error::msg)?;
        let output = serde_json::to_vec(&reply)?;
        anyhow::ensure!(
            output.len() <= warden::parent_mailbox::MAX_FRAME_BYTES,
            "reply exceeds mailbox bound"
        );
        for byte in output {
            write(0x521, byte);
        }
        write(0x522, 1);
    }
}
fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if let Err(error) = run() {
        eprintln!("parent stopped: {error}");
        std::process::exit(1);
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        eprintln!("Unsupported: parent mailbox requires Linux x86_64");
        std::process::exit(1);
    }
}
