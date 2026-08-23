class Lading < Formula
  desc "Deterministic compliance evidence for binary vulnerability triage"
  homepage "https://github.com/gautamtalksdev/lading"
  license "Apache-2.0"

  on_macos do
    on_intel do
      url "https://github.com/gautamtalksdev/lading/releases/download/v0.1.0/lading_0.1.0_darwin_amd64.tar.gz"
      sha256 "REPLACE_ON_RELEASE"
    end
    on_arm do
      url "https://github.com/gautamtalksdev/lading/releases/download/v0.1.0/lading_0.1.0_darwin_arm64.tar.gz"
      sha256 "REPLACE_ON_RELEASE"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/gautamtalksdev/lading/releases/download/v0.1.0/lading_0.1.0_linux_amd64.tar.gz"
      sha256 "REPLACE_ON_RELEASE"
    end
    on_arm do
      url "https://github.com/gautamtalksdev/lading/releases/download/v0.1.0/lading_0.1.0_linux_arm64.tar.gz"
      sha256 "REPLACE_ON_RELEASE"
    end
  end

  def install
    bin.install "lading"
  end

  test do
    assert_match "What LADING cannot do", shell_output("#{bin}/lading scan --help 2>&1", 2)
  end
end
