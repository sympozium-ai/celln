# Homebrew formula template for the private sympozium-ai tap.
#
# The release workflow replaces TAG and REVISION before publishing this file to
# the tap. A private repository must be fetched over the caller's authenticated
# SSH Git transport; a public GitHub tarball URL would make `brew install` fail
# even when the user can clone the repository.
class Cellulose < Formula
  desc "Run agents in hardware-isolated cells with attested, revocable tools"
  homepage "https://github.com/sympozium-ai/cellulose"
  url "git@github.com:sympozium-ai/cellulose.git",
      using:    :git,
      tag:      "v0.2.0",
      revision: "0000000000000000000000000000000000000000"
  license "Apache-2.0"

  depends_on "cpio"
  depends_on "e2fsprogs"
  depends_on "rustup"

  def install
    # Use a private build-local Rustup home: brewing must not mutate the
    # caller's own toolchain selection. `cell agent` still explains the one
    # target its local build plane needs at run time.
    ENV["RUSTUP_HOME"] = buildpath/"rustup"
    ENV["CARGO_HOME"] = buildpath/"cargo"
    system "rustup", "toolchain", "install", "stable", "--profile", "minimal",
           "--target", "x86_64-unknown-linux-musl"
    system "cargo", "+stable", "install", "--path", "crates/nous-cli", "--root", prefix,
           "--locked"
    guest_bin = buildpath/"guest-bin"
    system "cargo", "+stable", "install", "--path", "crates/pilot", "--root", guest_bin,
           "--target", "x86_64-unknown-linux-musl", "--bin", "nous-pilot", "--bin", "pilot-fetch",
           "--locked"

    pkgshare.install "scripts", "guest"
    (pkgshare/"pilot").install guest_bin/"bin/nous-pilot"
    (pkgshare/"pilot").install guest_bin/"bin/pilot-fetch"
  end

  def caveats
    <<~EOS
      `cell agent` builds generated programs as static musl binaries. Set up
      the same target in your user Rust toolchain once:

        rustup target add x86_64-unknown-linux-musl

      Sealing cells also needs Linux with readable /dev/kvm:

        cell doctor
    EOS
  end

  test do
    assert_match "cell", shell_output("#{bin}/cell --version")
    (testpath/"agent.toml").write shell_output("#{bin}/cell spec init")
    assert_match "my-agent", shell_output("#{bin}/cell spec check agent.toml --no-json")
  end
end
