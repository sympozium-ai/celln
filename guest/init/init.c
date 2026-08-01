/* Nouscell guest init — the smallest userspace that can prove things.
 *
 * This is the guest-side end of the test harness. It exists so claims about
 * what a *real* guest can and cannot do are made by guest code actually trying,
 * rather than by assertion on the host side — the same discipline as the
 * hostile-guest proof in warden's KVM backend.
 *
 * Freestanding on purpose: no libc, raw syscalls only. There is no toolchain to
 * install, nothing to keep in sync with the host distro, and the binary is a
 * few KiB. `pilot` will eventually be the real occupant of this slot; this is
 * the scaffold that lets the VFS<->memslot join be tested before pilot exists.
 *
 * Protocol with the host: every observation is printed to the console as a
 * line starting with "NOUS:" so the host can assert on it without parsing
 * kernel log noise. The last thing we do is reboot, which the host sees as a
 * clean KVM shutdown exit.
 */

#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_mmap 9
#define SYS_exit 60
#define SYS_mount 165
#define SYS_reboot 169

#define O_RDONLY 0
#define O_RDWR 2

#define PROT_READ 0x1
#define PROT_EXEC 0x4
#define MAP_PRIVATE 0x02

#define REBOOT_MAGIC1 0xfee1dead
#define REBOOT_MAGIC2 672274793
#define REBOOT_CMD_RESTART 0x01234567

static long sys(long n, long a, long b, long c, long d, long e, long f) {
	long ret;
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	__asm__ volatile("syscall"
	                 : "=a"(ret)
	                 : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
	                 : "rcx", "r11", "memory");
	return ret;
}

static int console = 1;

static unsigned long slen(const char *s) {
	unsigned long n = 0;
	while (s[n]) n++;
	return n;
}

static void out(const char *s) { sys(SYS_write, console, (long)s, slen(s), 0, 0, 0); }

/* Report an observation the host can assert on. */
static void report(const char *key, const char *val) {
	out("NOUS:");
	out(key);
	out("=");
	out(val);
	out("\n");
}

void _start(void) {
	/* devtmpfs gives us /dev/console; the kernel does not open it for us
	 * because our initramfs cannot carry device nodes. */
	sys(SYS_mount, (long) "devtmpfs", (long) "/dev", (long) "devtmpfs", 0, 0, 0);
	long fd = sys(SYS_open, (long) "/dev/console", O_RDWR, 0, 0, 0, 0);
	if (fd >= 0) console = (int)fd;

	report("init", "alive");

	/* Prove we are real userspace with working syscalls: an anonymous
	 * mapping, which is the same machinery the VFS<->memslot join will
	 * exercise against a tool file. */
	long p = sys(SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE | 0x20 /*ANON*/, -1, 0);
	report("mmap_anon", p > 0 ? "ok" : "fail");

	/* If the host has staged a tool for us, read its first bytes and echo
	 * them. Once the join exists, this same path becomes: mmap it
	 * PROT_EXEC and confirm the pages are the sealed memslot, not a copy. */
	long tf = sys(SYS_open, (long) "/tools/probe", O_RDONLY, 0, 0, 0, 0);
	if (tf >= 0) {
		report("tool_open", "ok");
		sys(SYS_close, tf, 0, 0, 0, 0, 0);
	} else {
		report("tool_open", "absent");
	}

	out("NOUS:done\n");
	sys(SYS_reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, REBOOT_CMD_RESTART, 0, 0, 0);
	sys(SYS_exit, 0, 0, 0, 0, 0, 0);
	for (;;) {}
}
