# Interim Homebrew formula (personal tap) — target is homebrew-core.
#
# Install today (no tap repo required):
#   brew install --formula ./packaging/homebrew/ownlock.rb
#
# Or publish a tap repo named homebrew-ownlock, then:
#   brew tap thebscolaro/ownlock
#   brew install ownlock
#
# Points at the latest *published* PyPI release (0.2.2). Bump url/sha/version
# when cutting the next release.

class Ownlock < Formula
  include Language::Python::Virtualenv

  desc "Cross-platform local secret broker for developers and AI agents"
  homepage "https://github.com/thebscolaro/ownlock"
  url "https://files.pythonhosted.org/packages/2f/4d/e33605f2c084fa4cf2feffe09a4ef8537862dd6cbd59137c236957070a9e/ownlock-0.2.2.tar.gz"
  sha256 "51218f1c1c470cc047d7ca941f6f2f28c36fdb1cd73658ceeef408b0ae4b0188"
  license "MIT"
  version "0.2.2"

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
