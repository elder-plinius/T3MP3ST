# T3MP3ST Install Matrix

Use this as the team-facing view of what a workstation needs. The UI and API remain useful without every binary installed, but local command readiness improves as these tools appear on `PATH`.

| Lane | Tools | macOS | Linux Notes | Execution |
| --- | --- | --- | --- | --- |
| Core evidence | `file`, `curl`, `dig`, `host`, `whois`, `openssl` | Usually present or `brew install bind openssl@3` | Usually package-manager available | Mixed local and receipt-gated |
| Web/API recon | `nmap`, `subfinder`, `httpx`, `naabu`, `katana`, `nuclei` | Homebrew plus ProjectDiscovery tap | Prefer distro packages or upstream release binaries | Receipt-gated |
| Web/API pressure | `ffuf`, `gobuster`, `feroxbuster`, `nikto`, `dalfox`, `sqlmap` | Homebrew | Distro packages, Go installs, or upstream releases | Receipt-gated |
| Supply chain | `semgrep`, `gitleaks`, `trufflehog`, `trivy`, `syft`, `grype`, `osv-scanner` | Homebrew or pipx where noted | Distro packages, pipx, or upstream releases | Mostly local-read |
| Cloud/IaC | `checkov`, `prowler` | Homebrew or pipx | pipx usually cleanest | Local-read or receipt-gated cloud account checks |
| AI/agent | `garak`, `promptfoo` | pipx and npm | pipx and npm | Receipt-gated model/system probing |
| Smart contract | `slither`, `myth`, `echidna`, `forge`, `cast`, `solhint` | pipx, Homebrew tap, Foundry installer, npm | pipx, upstream releases, Foundry installer, npm | Local-read plus receipt-gated chain calls |
| Crypto audit | `john`, `hashcat` | Homebrew | Distro packages | Receipt-gated, never store recovered secrets |
| Reverse/mobile/fuzz | `radamsa`, `afl-fuzz`, `r2`, `apktool`, `jadx`, `exiftool`, `binwalk`, `yara` | Homebrew | Distro packages or upstream releases | Local-read lab artifacts |
| Gated/import | `msfconsole`, `hydra`, `bloodhound` | Optional | Optional | Catalog-only or import-only until narrow adapters exist |

## Kali Linux / Debian

Kali is a supported platform — the codebase has no Windows-only runtime paths —
but stock Kali/Debian `nodejs` packages are usually older than the required
floor and will make `npm install` or startup fail partway. Use NodeSource or
nvm:

```bash
# Node.js 22.x via NodeSource (Debian/Ubuntu line)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo bash -
sudo apt-get install -y nodejs build-essential
node --version   # must be >= 22.19.0

# or via nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/master/install.sh | bash
nvm install 22 && nvm use 22
```

Then from the repo:

```bash
npm install
npm run doctor     # flags a too-old Node BEFORE the confusing failures it causes
npm run server
```

`build-essential` covers any native module rebuilds. Most arsenal tools in the
table above are already packaged on Kali (`nmap`, `sqlmap`, `nikto`, `hashcat`,
`john`, `binwalk`, `exiftool`, ...) — run `npm run doctor` and
`npm run arsenal:doctor` to see exactly what is missing rather than installing
everything blindly.

If a run still fails, include the actual output (`npm run doctor`, the failing
command, and the last ~50 log lines) in your bug report — "it doesn't complete"
with no output is not actionable.

## macOS Homebrew Repair

If Homebrew is owned by a different local user, installs may fail with `Cellar is not writable` or tap permission errors. Repair the prefix before installing tools:

```bash
sudo chown -R "$(whoami)":admin /opt/homebrew
brew doctor
```

## Minimum Useful Workstation

For a first team preview, prioritize:

```bash
brew install nmap ffuf nuclei semgrep gitleaks trivy syft grype exiftool yara
npm install -g promptfoo
pipx install garak
```

This gives the team a practical web, repo, evidence, and AI-boundary loop without waiting on the full arsenal.
