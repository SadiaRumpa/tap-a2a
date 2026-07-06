class TamarinProver < Formula
  desc "Automated security protocol verification tool"
  homepage "https://tamarin-prover.com/"
  url "https://github.com/tamarin-prover/tamarin-prover/archive/refs/tags/1.12.0.tar.gz"
  sha256 "35f0262e770db3632fcb297deb6ecc2d7c724c693fecfe97892e8224fa161956"
  head "https://github.com/tamarin-prover/tamarin-prover.git", branch: "master"

  depends_on "haskell-stack" => :build
  depends_on "npm" => :build
  depends_on "graphviz"
  depends_on "maude"

  # doi "10.1109/CSF.2012.25"
  # tag "security"

  def install
    # make frontend
    system "make", "frontend"
    # Let `stack` handle its own parallelization
    jobs = ENV.make_jobs
    system "stack", "-j#{jobs}", "setup"
    args = []
    unless OS.mac?
      args << "--extra-include-dirs=#{Formula["zlib"].include}" << "--extra-lib-dirs=#{Formula["zlib"].lib}"
    end
    system "stack", "-j#{jobs}", *args, "install", "--flag", "tamarin-prover:threaded"

    bin.install Dir[".brew_home/.local/bin/*"]
  end

  test do
    system "#{bin}/tamarin-prover", "test"
  end
end
