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

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_mmap 9
#define SYS_nanosleep 35
#define SYS_exit 60
#define SYS_mount 165
#define SYS_reboot 169
#define SYS_finit_module 313

#define O_RDONLY 0
#define O_RDWR 2

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define MAP_PRIVATE 0x02
#define MAP_SHARED 0x01
#define MAP_ANONYMOUS 0x20

/* Where warden seals the first lent tool. Must match TOOL_WINDOW_GPA in
 * crates/warden/src/vmm/boot.rs — the coupling is deliberate and checked by
 * the magic below: if the two ever drift, the guest reads garbage and says so
 * rather than silently passing. */
#define TOOL_GPA 0x18000000UL
#define TOOL_MAGIC "NOUSTOOL"
/* Offset within the sealed page of a function the guest is meant to call. */
#define TOOL_FN_OFF 16
#define TOOL_FN_EXPECT 0x5a

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

static void report_hex(const char *key, unsigned long v) {
	static const char digits[] = "0123456789abcdef";
	char buf[17];
	int i;
	for (i = 0; i < 16; i++) buf[i] = digits[(v >> ((15 - i) * 4)) & 0xf];
	buf[16] = 0;
	out("NOUS:");
	out(key);
	out("=");
	out(buf);
	out("\n");
}

static int same(const char *a, const char *b, unsigned long n) {
	for (unsigned long i = 0; i < n; i++)
		if (a[i] != b[i]) return 0;
	return 1;
}

/* The VFS<->memslot join, asked as a question the guest can answer.
 *
 * A sealed tool page-set lives in this guest's physical address space at
 * TOOL_GPA, outside the e820 map. If a userspace mapping of it resolves to
 * the *sealed memslot*, we see the real bytes and the seal governs what we can
 * do with them. If instead the kernel hands us a page-cache copy, we would
 * still see plausible bytes -- and a write would succeed. That difference is
 * the whole claim, so we test it by writing.
 *
 * /dev/mem is not the production path (that is a filesystem, via DAX). It is
 * the shortest mapping that is unambiguously direct, so it isolates the
 * question "does the seal survive a userspace mapping" from the separate
 * question "which filesystem mechanism gets us there". */
static void probe_sealed_tool(void) {
	long fd = sys(SYS_open, (long) "/dev/mem", O_RDWR, 0, 0, 0, 0);
	if (fd < 0) {
		report("seal_probe", "no-devmem");
		return;
	}
	volatile char *p = (volatile char *)sys(SYS_mmap, 0, 4096,
	                                        PROT_READ | PROT_WRITE | PROT_EXEC,
	                                        MAP_SHARED, fd, TOOL_GPA);
	if ((unsigned long)p > (unsigned long)-4096L) {
		report("seal_probe", "mmap-failed");
		sys(SYS_close, fd, 0, 0, 0, 0, 0);
		return;
	}
	report("seal_probe", "mapped");

	/* 1. Are these the real sealed bytes, or something else?
	 *
	 * Never execute or write past this check. When the sealed region holds
	 * something other than the raw probe tool -- the DAX test seals a
	 * filesystem image, whose offset 16 is ext2 metadata -- jumping to it
	 * kills init before the rest of the run happens, and the failure looks
	 * like the later probe never ran. */
	char got[8];
	for (int i = 0; i < 8; i++) got[i] = p[i];
	if (!same(got, TOOL_MAGIC, 8)) {
		report("tool_magic", "not-probe-payload");
		sys(SYS_close, fd, 0, 0, 0, 0, 0);
		return;
	}
	report("tool_magic", "match");

	/* 2. Can we execute out of the mapping? The sealed page carries a
	 *    function that returns a known value. */
	int (*fn)(void) = (int (*)(void))(p + TOOL_FN_OFF);
	int rv = fn();
	report("tool_exec", rv == TOOL_FN_EXPECT ? "ok" : "wrong-value");
	report_hex("tool_exec_rv", (unsigned long)rv);

	/* 3. The actual test. Write to it. Guest-side this is a legal write to
	 *    a writable mapping; nothing in the guest refuses it. Then read the
	 *    byte back: if the seal held below us, it is unchanged. */
	char before = p[0];
	p[0] = 0x41;
	char after = p[0];
	report("seal_write_landed", after == before ? "no" : "YES");
	report_hex("seal_byte_before", (unsigned char)before);
	report_hex("seal_byte_after", (unsigned char)after);

	sys(SYS_close, fd, 0, 0, 0, 0, 0);
}

/* Echo lines of `path` containing `needle`, prefixed so the host can find them.
 * Diagnostics for the pmem chain: when a device does not appear, the reason is
 * in the kernel's own bookkeeping, not in anything the guest can infer. */
static void grep_file(const char *tag, const char *path, const char *needle) {
	static char buf[8192];
	long fd = sys(SYS_open, (long)path, O_RDONLY, 0, 0, 0, 0);
	if (fd < 0) {
		report(tag, "unreadable");
		return;
	}
	/* seq_files (procfs) return a chunk at a time, not the whole file, so a
	 * single read() silently truncates and looks like "the entry is absent". */
	long n = 0, k;
	while (n < (long)sizeof(buf) - 1 &&
	       (k = sys(SYS_read, fd, (long)(buf + n), sizeof(buf) - 1 - n, 0, 0, 0)) > 0) {
		n += k;
	}
	sys(SYS_close, fd, 0, 0, 0, 0, 0);
	if (n <= 0) {
		report(tag, "empty");
		return;
	}
	buf[n] = 0;
	unsigned long nl = slen(needle);
	long start = 0;
	for (long i = 0; i <= n; i++) {
		if (buf[i] != '\n' && buf[i] != 0) continue;
		buf[i] = 0;
		for (long j = start; j + (long)nl <= i; j++) {
			if (same(&buf[j], needle, nl)) {
				out("NOUS:");
				out(tag);
				out("=");
				out(&buf[start]);
				out("\n");
				break;
			}
		}
		start = i + 1;
	}
}

static void sleep_ms(long ms) {
	long ts[2];
	ts[0] = ms / 1000;
	ts[1] = (ms % 1000) * 1000000L;
	sys(SYS_nanosleep, (long)ts, 0, 0, 0, 0, 0);
}

static int insmod(const char *path) {
	long fd = sys(SYS_open, (long)path, O_RDONLY, 0, 0, 0, 0);
	if (fd < 0) return -1;
	long rc = sys(SYS_finit_module, fd, (long) "", 0, 0, 0, 0);
	sys(SYS_close, fd, 0, 0, 0, 0, 0);
	/* -EEXIST means already loaded, which is success for our purposes. */
	return (rc == 0 || rc == -17) ? 0 : (int)rc;
}

/* The production-shaped join: reach the sealed pages through a FILE PATH.
 *
 * The /dev/mem probe answered "does the seal survive a userspace mapping".
 * This answers the separate question the build plan actually poses: can a
 * guest open("/tools/probe") and mmap(PROT_EXEC) it and land on the sealed
 * memslot, rather than on a page-cache copy of it?
 *
 * The chain: the sealed region is declared to the kernel as persistent memory
 * (memmap= on the cmdline), the nvdimm modules turn it into /dev/pmem0, and an
 * ext2 image inside it is mounted with dax=always. DAX is precisely the
 * property we need -- it means "map the file's pages directly, do not go
 * through the page cache".
 *
 * The test that distinguishes direct from copied is the WRITE. A page-cache
 * copy would absorb it silently and the host would count no refusal; a direct
 * mapping puts the guest's store against a read-only memslot, where the
 * hardware refuses it. Magic and execution alone would pass either way.
 */
static void probe_tool_by_path(void) {
	sys(SYS_mount, (long) "proc", (long) "/proc", (long) "proc", 0, 0, 0);
	sys(SYS_mount, (long) "sysfs", (long) "/sys", (long) "sysfs", 0, 0, 0);

	report_hex("mod_libnvdimm", (unsigned long)insmod("/modules/libnvdimm.ko"));
	report_hex("mod_nd_pmem", (unsigned long)insmod("/modules/nd_pmem.ko"));
	report_hex("mod_nd_e820", (unsigned long)insmod("/modules/nd_e820.ko"));
	report_hex("mod_ramdax", (unsigned long)insmod("/modules/ramdax.ko"));

	/* Does the kernel see our region as legacy persistent memory at all, and
	 * did the arch code create the platform device nd_e820 binds to? */
	grep_file("iomem", "/proc/iomem", "ersistent");
	long pd = sys(SYS_open, (long) "/sys/devices/platform/e820_pmem/uevent", O_RDONLY, 0, 0, 0, 0);
	report("e820_pmem_dev", pd >= 0 ? "present" : "absent");
	if (pd >= 0) sys(SYS_close, pd, 0, 0, 0, 0, 0);

	/* Device probing is asynchronous; wait for devtmpfs to publish it. */
	long dev = -1;
	for (int i = 0; i < 50 && dev < 0; i++) {
		dev = sys(SYS_open, (long) "/dev/pmem0", O_RDONLY, 0, 0, 0, 0);
		if (dev < 0) sleep_ms(20);
	}
	if (dev < 0) {
		report("dax", "no-pmem-device");
		return;
	}
	sys(SYS_close, dev, 0, 0, 0, 0, 0);
	report("dax_pmem", "present");

	/* Mounted read-write on purpose: we need a writable mapping to test the
	 * seal, and ext2 has no journal to replay against a device whose writes
	 * are being dropped. */
	long rc = sys(SYS_mount, (long) "/dev/pmem0", (long) "/tools", (long) "ext2", 0,
	              (long) "dax=always", 0);
	if (rc != 0) {
		/* The ext2 image is handled by the ext4 driver on most builds. */
		rc = sys(SYS_mount, (long) "/dev/pmem0", (long) "/tools", (long) "ext4", 0,
		         (long) "dax=always", 0);
	}
	if (rc != 0) {
		report("dax_mount", "failed");
		report_hex("dax_mount_err", (unsigned long)-rc);
		return;
	}
	report("dax_mount", "ok");

	long fd = sys(SYS_open, (long) "/tools/probe", O_RDWR, 0, 0, 0, 0);
	if (fd < 0) {
		report("dax_open", "failed");
		return;
	}
	report("dax_open", "ok");

	volatile char *p = (volatile char *)sys(SYS_mmap, 0, 4096,
	                                        PROT_READ | PROT_WRITE | PROT_EXEC,
	                                        MAP_SHARED, fd, 0);
	if ((unsigned long)p > (unsigned long)-4096L) {
		report("dax_mmap", "failed");
		sys(SYS_close, fd, 0, 0, 0, 0, 0);
		return;
	}
	report("dax_mmap", "ok");

	char got[8];
	for (int i = 0; i < 8; i++) got[i] = p[i];
	report("dax_magic", same(got, TOOL_MAGIC, 8) ? "match" : "MISMATCH");

	int (*fn)(void) = (int (*)(void))(p + TOOL_FN_OFF);
	report("dax_exec", fn() == TOOL_FN_EXPECT ? "ok" : "wrong-value");

	/* The decisive step: write through the file mapping. */
	char before = p[0];
	p[0] = 0x41;
	char after = p[0];
	report("dax_write_landed", after == before ? "no" : "YES");
	report_hex("dax_byte_after", (unsigned char)after);

	/* The kill wire, against a guest that is holding the tool open and
	 * mapped. Printing this line is the signal for the host to delete the
	 * memslot out from under us; whatever we can still see afterwards is
	 * the answer to "does revocation reach a running cell". */
	report("dax_revoke_ready", "now");
	sleep_ms(100);
	char post[8];
	for (int i = 0; i < 8; i++) post[i] = p[i];
	report("dax_after_revoke", same(post, TOOL_MAGIC, 8) ? "STILL-READABLE" : "revoked");

	sys(SYS_close, fd, 0, 0, 0, 0, 0);
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
	long p = sys(SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	report("mmap_anon", p > 0 ? "ok" : "fail");

	probe_sealed_tool();
	probe_tool_by_path();

	out("NOUS:done\n");
	sys(SYS_reboot, REBOOT_MAGIC1, REBOOT_MAGIC2, REBOOT_CMD_RESTART, 0, 0, 0);
	sys(SYS_exit, 0, 0, 0, 0, 0, 0);
	for (;;) {}
}
