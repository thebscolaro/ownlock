# Interim Homebrew formula (personal tap) — target is homebrew-core.
#
# Install today (no tap repo required):
#   brew install --formula ./packaging/homebrew/ownlock.rb
#
# Or publish a tap repo named homebrew-ownlock, then:
#   brew tap thebscolaro/ownlock
#   brew install ownlock
#
# Points at the latest *published* PyPI release (0.3.1 until 0.3.2 sdist lands).
# Bump url/sha/version after PyPI publish — see packaging/README.md.
# Cursor shield on 0.3.1 can lock the agent: upgrade to 0.3.2 and `ownlock shield --force`.

class Ownlock < Formula
  include Language::Python::Virtualenv

  desc "Cross-platform local secret broker for developers and AI agents"
  homepage "https://github.com/thebscolaro/ownlock"
  url "https://files.pythonhosted.org/packages/8a/84/8fbff5c2722e60869a6fe464adc36b2575804005a8d476dc7c8c7fd58435/ownlock-0.3.1.tar.gz"
  sha256 "a6a515d170a6e72cfd459580bb1a16619ed68b317e8698c77455fa703a57b301"
  license "MIT"
  version "0.3.1"

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
