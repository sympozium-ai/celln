# Homebrew formula for the public sympozium-ai tap.
class Celln < Formula
  desc "Run agents in hardware-isolated cells with attested, revocable tools"
  homepage "https://github.com/sympozium-ai/celln"
  url "https://github.com/sympozium-ai/celln/archive/refs/tags/v0.4.0.tar.gz"
  sha256 "136f67e5940ca97df70d0e35a1f1aba7edfc198b91392c53feb2b3bafb0addc5"
  license "Apache-2.0"

  depends_on "cpio"
  depends_on "e2fsprogs"
  depends_on "rustup"

  def install
    # Use a private build-local Rustup home: brewing must not mutate the
    # caller's own toolchain selection. `celln agent` still explains the one
    # target its local build plane needs at run time.
    ENV["RUSTUP_HOME"] = buildpath/"rustup"
    ENV["CARGO_HOME"] = buildpath/"cargo"
    system "rustup", "toolchain", "install", "stable", "--profile", "minimal",
           "--target", "x86_64-unknown-linux-musl"
    system "cargo", "+stable", "install", "--path", "crates/celln-cli", "--root", prefix,
           "--locked"
    guest_bin = buildpath/"guest-bin"
    system "cargo", "+stable", "install", "--path", "crates/celln-pilot", "--root", guest_bin,
           "--target", "x86_64-unknown-linux-musl", "--bin", "celln-pilot", "--bin", "pilot-fetch",
           "--locked"

    pkgshare.install "scripts", "guest"
    (pkgshare/"pilot").install guest_bin/"bin/celln-pilot"
    (pkgshare/"pilot").install guest_bin/"bin/pilot-fetch"
  end

  def caveats
    <<~EOS
      `celln agent` builds generated programs as static musl binaries. Set up
      the same target in your user Rust toolchain once:

        rustup target add x86_64-unknown-linux-musl

      Sealing cells also needs Linux with readable /dev/kvm:

        celln doctor
    EOS
  end

  test do
    assert_match "celln", shell_output("#{bin}/celln --version")
    (testpath/"agent.toml").write shell_output("#{bin}/celln spec init")
    assert_match "my-agent", shell_output("#{bin}/celln spec check agent.toml --no-json")
  end
end
