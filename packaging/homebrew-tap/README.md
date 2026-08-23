# Homebrew tap

```bash
brew tap gautamtalksdev/tap
brew install lading
```

Formula: [`Formula/lading.rb`](Formula/lading.rb)

GoReleaser updates URL and SHA256 on each release when `brews` is configured in
[`.goreleaser.yaml`](../../.goreleaser.yaml). Until the first release, install from
source:

```bash
go install github.com/gautamtalksdev/lading/cmd/lading@latest
```
