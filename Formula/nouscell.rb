# Homebrew formula for nouscell.
#
#   brew install sympozium-ai/tap/nouscell
#
# Builds from source rather than shipping a bottle: this is pre-alpha and the
# hardware path is Linux-only, so a bottle would mostly be a way to ship the
# wrong thing to the wrong machine.
class Nouscell < Formula
  desc "Run agents in hardware-isolated cells with attested, revocable tools"
  homepage "https://github.com/sympozium-ai/nouscell"
  url "https://github.com/sympozium-ai/nouscell/archive/refs/tags/v0.1.0.tar.gz"
  # Replaced by the release workflow; `brew audit` will flag it until then.
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"
  head "https://github.com/sympozium-ai/nouscell.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/nous-cli")
    doc.install "README.md", "docs"
  end

  def caveats
    on_macos do
      <<~EOS
        Hardware isolation needs Linux with /dev/kvm, so on macOS `nous` can
        validate specs and run `nous demo`, but not seal cells.

          nous doctor    # says exactly what this machine can do
      EOS
    end
    on_linux do
      <<~EOS
        Sealing cells needs read access to /dev/kvm. If `nous doctor` reports it
        is present but not readable:

          sudo usermod -aG kvm $USER    # then log out and back in

        Get started:

          nous spec init > agent.toml
          nous spec check agent.toml
      EOS
    end
  end

  test do
    # Works everywhere, hardware or not.
    assert_match "nous", shell_output("#{bin}/nous --version")
    (testpath/"agent.toml").write shell_output("#{bin}/nous spec init")
    assert_match "my-agent", shell_output("#{bin}/nous spec check agent.toml --no-json")
    # `doctor` exits 3 on a host that cannot seal cells, which is not a failure.
    shell_output("#{bin}/nous doctor --no-json", 3) if !File.exist?("/dev/kvm")
  end
end
