# Interim Homebrew formula (personal tap) — target is homebrew-core.
#
# Install today (no tap repo required):
#   brew install --formula ./packaging/homebrew/ownlock.rb
#
# Or publish a tap repo named homebrew-ownlock, then:
#   brew tap thebscolaro/ownlock
#   brew install ownlock
#
# Points at the latest *published* PyPI release (0.3.2).
# Bump url/sha/version when cutting the next release — see packaging/README.md.

class Ownlock < Formula
  include Language::Python::Virtualenv

  desc "Cross-platform local secret broker for developers and AI agents"
  homepage "https://github.com/thebscolaro/ownlock"
  url "https://files.pythonhosted.org/packages/fb/6b/638e059e730782d47b7c4459b3030900aa47b65f1baa5bac713fe050263e/ownlock-0.3.2.tar.gz"
  sha256 "2effedcec0fceea600267695da371e32d027d2c191b334fbca7694b3776c44e6"
  license "MIT"
  version "0.3.2"

  depends_on "python@3.12"

  def install
    # Install from PyPI so runtime deps resolve cleanly without vendoring every wheel.
    virtualenv_create(libexec, "python3.12")
    system libexec/"bin/pip", "install", "--upgrade", "pip"
    system libexec/"bin/pip", "install", "ownlock==#{version}"
    bin.install_symlink libexec/"bin/ownlock"
    mcp = libexec/"bin/ownlock-mcp"
    bin.install_symlink mcp if mcp.exist?
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/ownlock --version")
  end
end
