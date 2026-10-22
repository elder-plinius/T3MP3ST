#!/usr/bin/env bash
# install-tools.sh — arm the workstation with the t3mp3st specialist arsenal.
#
# The executable form of docs/INSTALL_MATRIX.md: idempotent (skips anything already on PATH),
# lane-grouped, macOS/Homebrew-first with pipx/npm where the matrix says so. For a fully
# reproducible Linux arsenal use the Kali+ image instead (npm run tools:build).
#
# Usage:
#   scripts/install-tools.sh              # default: recon + web + secrets (the offensive loop)
#   scripts/install-tools.sh --web        # recon + web pressure tools only
#   scripts/install-tools.sh --min        # INSTALL_MATRIX "minimum useful workstation"
#   scripts/install-tools.sh --all        # everything in the matrix
#   scripts/install-tools.sh --recon|--crypto|--re|--cloud|--ai|--contract
#   scripts/install-tools.sh --list       # dry-run: show what WOULD be installed
#
# Not run with -e: a single failed install must not abort the rest.
set -uo pipefail

GROUP="default"; LIST=""
for a in "$@"; do case "$a" in
  --web) GROUP="web";; --min) GROUP="min";; --all) GROUP="all";;
  --recon) GROUP="recon";; --web-only) GROUP="webonly";;
  --crypto) GROUP="crypto";; --re) GROUP="re";; --cloud) GROUP="cloud";;
  --ai) GROUP="ai";; --contract) GROUP="contract";; --secrets) GROUP="secrets";;
  --list|-n) LIST=1;;
  -h|--help) sed -n '2,18p' "$0"; exit 0;;
  *) echo "unknown flag: $a (try --help)"; exit 2;;
esac; done

have(){ command -v "$1" >/dev/null 2>&1; }

# need <binary> <installer cmd...>
need(){
  local bin="$1"; shift
  if have "$bin"; then echo "  ✓ $bin"; return 0; fi
  if [ -n "$LIST" ]; then echo "  + $bin  ←  $*"; return 0; fi
  echo "  → $bin : $*"
  if "$@"; then echo "    ok"; else echo "    FAIL ($bin) — see output above / docs/INSTALL_MATRIX.md"; fi
}

# Prereq managers (warn, don't fail — a tool that needs a missing manager just FAILs its line).
# Kali/Debian: most tools are distro-packaged, so prefer apt when brew is absent.
APT=""
if have apt-get; then APT="apt-get"; elif have apt; then APT="apt"; fi
SUDO=""
if [ -n "$APT" ] && [ "$(id -u)" -ne 0 ] && have sudo; then SUDO="sudo"; fi
apt_install(){ $SUDO $APT update && $SUDO $APT install -y "$@"; }
# brew helper — on Kali it will warn if missing, but apt branch below handles the same binaries.
if ! have brew && [ -z "$APT" ] && [ -z "$LIST" ]; then echo "⚠ Homebrew not found and no apt — brew-based tools will FAIL. https://brew.sh"; fi
PIPX=pipx; have pipx || PIPX="python3 -m pipx"   # fall back if pipx isn't a shim

recon(){    echo "── 🔍 recon/osint ──"
  if [ -n "$APT" ] && ! have brew; then
    need nmap        apt_install nmap
    need httpx       apt_install httpx 2>/dev/null || need httpx brew install projectdiscovery/tap/httpx
    need naabu       apt_install naabu 2>/dev/null || need naabu brew install projectdiscovery/tap/naabu
    need katana      apt_install katana 2>/dev/null || need katana brew install projectdiscovery/tap/katana
    need subfinder   apt_install subfinder 2>/dev/null || need subfinder brew install projectdiscovery/tap/subfinder
    need nuclei      apt_install nuclei 2>/dev/null || need nuclei brew install nuclei
  else
    need nmap        brew install nmap
    need httpx       brew install projectdiscovery/tap/httpx
    need naabu       brew install projectdiscovery/tap/naabu
    need katana      brew install projectdiscovery/tap/katana
    need subfinder   brew install projectdiscovery/tap/subfinder
    need nuclei      brew install nuclei
  fi
}
web(){      echo "── 🕸️ web exploitation ──"
  if [ -n "$APT" ] && ! have brew; then
    need ffuf        apt_install ffuf
    need gobuster    apt_install gobuster
    need feroxbuster apt_install feroxbuster 2>/dev/null || need feroxbuster brew install feroxbuster
    need nikto       apt_install nikto
    need dalfox      apt_install dalfox 2>/dev/null || need dalfox brew install dalfox
    need sqlmap      apt_install sqlmap
  else
    need ffuf        brew install ffuf
    need gobuster    brew install gobuster
    need feroxbuster brew install feroxbuster
    need nikto       brew install nikto
    need dalfox      brew install dalfox
    need sqlmap      brew install sqlmap
  fi
}
secrets(){  echo "── 🔑 secrets/supply-chain ──"
  if [ -n "$APT" ] && ! have brew; then
    need semgrep     apt_install semgrep 2>/dev/null || need semgrep brew install semgrep
    need gitleaks    apt_install gitleaks 2>/dev/null || need gitleaks brew install gitleaks
    need trufflehog  apt_install trufflehog 2>/dev/null || need trufflehog brew install trufflehog
    need trivy       apt_install trivy 2>/dev/null || need trivy brew install trivy
    need syft        apt_install syft 2>/dev/null || need syft brew install syft
    need grype       apt_install grype 2>/dev/null || need grype brew install grype
    need osv-scanner apt_install osv-scanner 2>/dev/null || need osv-scanner brew install osv-scanner
  else
    need semgrep     brew install semgrep
    need gitleaks    brew install gitleaks
    need trufflehog  brew install trufflehog
    need trivy       brew install trivy
    need syft        brew install syft
    need grype       brew install grype
    need osv-scanner brew install osv-scanner
  fi
}
crypto(){   echo "── 🔐 crypto ──"
  if [ -n "$APT" ] && ! have brew; then
    need john        apt_install john
    need hashcat     apt_install hashcat
  else
    need john        brew install john
    need hashcat     brew install hashcat
  fi
}
re(){       echo "── ⚙️ reverse/mobile/fuzz ──"
  if [ -n "$APT" ] && ! have brew; then
    need radare2     apt_install radare2
    need binwalk     apt_install binwalk
    need exiftool    apt_install libimage-exiftool-perl
    need yara        apt_install yara
    need apktool     apt_install apktool
    need jadx        apt_install jadx 2>/dev/null || need jadx brew install jadx
    need radamsa     apt_install radamsa 2>/dev/null || need radamsa brew install radamsa
    need afl-fuzz    apt_install afl++ 2>/dev/null || need afl-fuzz brew install afl++
  else
    need radare2     brew install radare2
    need binwalk     brew install binwalk
    need exiftool    brew install exiftool
    need yara        brew install yara
    need apktool     brew install apktool
    need jadx        brew install jadx
    need radamsa     brew install radamsa
    need afl-fuzz    brew install afl++
  fi
}
cloud(){    echo "── ☁️ cloud/iac ──"
  need checkov     $PIPX install checkov
  need prowler     $PIPX install prowler
}
ai(){       echo "── 🤖 ai red-team (the +) ──"
  need garak       $PIPX install garak
  need promptfoo   npm install -g promptfoo
}
contract(){ echo "── 📜 smart-contract ──"
  need slither     $PIPX install slither-analyzer
  need myth        $PIPX install mythril
  need solhint     npm install -g solhint
  echo "  ℹ foundry (forge/cast): curl -L https://foundry.paradigm.xyz | bash && foundryup"
}
minimum(){  echo "── ⭐ minimum useful workstation (INSTALL_MATRIX) ──"
  need nmap brew install nmap;       need ffuf brew install ffuf
  need nuclei brew install nuclei;   need semgrep brew install semgrep
  need gitleaks brew install gitleaks; need trivy brew install trivy
  need syft brew install syft;       need grype brew install grype
  need exiftool brew install exiftool; need yara brew install yara
  need promptfoo npm install -g promptfoo
}

echo "T3MP3ST arsenal installer — group: $GROUP${LIST:+ (dry-run)}"
case "$GROUP" in
  default)  recon; web; secrets;;
  web)      recon; web;;
  webonly)  web;;
  min)      minimum;;
  recon)    recon;;  secrets) secrets;;  crypto) crypto;;
  re)       re;;     cloud)   cloud;;    ai)     ai;;  contract) contract;;
  all)      recon; web; secrets; crypto; re; cloud; ai; contract;;
esac

echo
echo "Done. Verify readiness with:  npm run arsenal:doctor"
