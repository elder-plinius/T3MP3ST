#!/usr/bin/env bash
#
# clean-export.sh — produce a PUBLIC, history-free export of t3mp3st from the
# current committed tree (HEAD), with every disclosure-hold, identity, home-path,
# held-vuln-target, and stale-number leak STRIPPED and GATED.
#
# WHY history-free: this repo's git history provably contains the coordinated-
# disclosure "wild-hunt" dossier and can NEVER be pushed public. This script
# exports tracked file CONTENT only, into a fresh single-commit repo.
#
# It NEVER adds a remote and NEVER pushes. After it finishes, review the export
# and push it to your PUBLIC repo yourself.
#
# Usage:  scripts/clean-export.sh [DEST_DIR]
#           DEST_DIR defaults to ~/Desktop/t3mp3st-public
#         env SKIP_BUILD=1  → skip npm install/build/test (leak + dep-free gates still run)
#
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${1:-$HOME/Desktop/t3mp3st-public}"
NEUTRAL_NAME="t3mp3st contributors"
NEUTRAL_EMAIL="t3mp3st@users.noreply.github.com"

# operator's real macOS username — leaks as the bare owner token in captured
# `ls -l`/`ps`/`lsof` tool output (e.g. "-rw-r--r--@ 1 faber wheel …"), which the
# /Users/ path scrub does NOT catch. Scrubbed whole-word below and gated for.
USER_TOK="$(id -un)"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }
say() { printf '\342\226\270 %s\n' "$*"; }

# ── internal scratch / stale / marketing-draft files: never ship ──────────────
EXCLUDE=(
  docs/NEXT_SESSION_PROMPT.md
  docs/XBOW_FRAMEWORK_ANALYSIS.md
  docs/SOTA_CLAIM.md
  docs/TWITTER_CLAIM_DRAFT.md
  docs/V5_PLAN.md
  bench/xbow/results/blackbox/SWEEP-RESULTS.md
  scripts/clean-export.sh   # the exporter itself: a public re-exporter isn't needed,
                            # and its denylist would otherwise reveal the held targets
)

# ── tokens that must NOT survive in the export (any hit FAILS the build) ───────
FORBIDDEN=(
  '/Users/'            # real home path (post-scrub must be 0)
  '/var/folders/'      # macOS per-UID temp-dir hash (machine fingerprint)
  'younger_plinius'    # internal monorepo dir
  '03-PLINYOS'         # internal monorepo nesting
  'elder_plinius'      # operator handle — de-pseudonymizes the held disclosures
  'younger-plinius'    # private GH org — would advertise the private repo
  'Slamtec' 'rplidar' 'unitree' 'micro-xrce' 'microxrce' 'Livox' 'Ouster'  # held wild-hunt targets
  '102-challenge' '93/102' '73/77' '69/73'   # stale pre-retraction XBEN numbers
)

# ── gitignored holds that must be ABSENT from the export (backstop assertion) ──
HOLDS=(
  bench/wild-hunt docs/disclosures .env .env.local .keys.local
  docs/V6_PLAN.md bench/decomposition-results bench/refusal-frontier bench/nyu
)

say "source : $SRC"
say "dest   : $DEST"

# 1) warn if HEAD is dirty — the export ships HEAD, so uncommitted scrubs won't land
if ! git -C "$SRC" diff --quiet HEAD 2>/dev/null; then
  red "WARNING: working tree differs from HEAD — the export uses HEAD content."
  red "         Commit your scrubs first, or they will NOT be in the export."
fi

# 2) fresh DEST
rm -rf "$DEST"
mkdir -p "$DEST"

# 3) export tracked HEAD content only (gitignored holds excluded by construction)
say "exporting tracked HEAD content (git archive — gitignored holds excluded)…"
git -C "$SRC" archive --format=tar HEAD | tar -x -C "$DEST"

# 4) drop internal scratch files
for f in "${EXCLUDE[@]}"; do
  if [[ -e "$DEST/$f" ]]; then rm -f "$DEST/$f"; say "excluded $f"; fi
done

# the npm alias for the exporter shouldn't ship (the exporter itself is excluded)
if [[ -f "$DEST/package.json" ]]; then
  perl -i -ne 'print unless /"export:clean"\s*:/' "$DEST/package.json"
fi

# 5) scrub home paths / internal nesting / temp-dirs / private GH org across TEXT files.
#    Select by EXTENSION via `find -exec ... {} +` (atomic, reliable) — do NOT content-sniff
#    with `grep -I` (false-flags transcripts as binary → skips → leaks the home path) and
#    do NOT use a `find | while read | perl` pipeline (a per-file subshell can silently skip
#    a file). -exec batches every matched file straight into perl in-place.
say "scrubbing paths, nesting, temp-dirs, and org refs across text files…"
# Two idempotent passes: the substitutions are no-ops once clean, and a second pass
# converges any file a single `find -exec` batch non-deterministically skipped. The
# leak GATE below is the real fail-safe — it refuses to finalize if anything survives.
for _pass in 1 2; do
USER_TOK="$USER_TOK" \
find "$DEST" -type f \( \
     -name '*.json'  -o -name '*.md'   -o -name '*.ts'   -o -name '*.tsx' -o -name '*.js'  \
  -o -name '*.jsx'  -o -name '*.mjs'  -o -name '*.cjs'  -o -name '*.html' -o -name '*.htm' \
  -o -name '*.css'  -o -name '*.scss' -o -name '*.sh'   -o -name '*.bash' -o -name '*.txt' \
  -o -name '*.yml'  -o -name '*.yaml' -o -name '*.toml' -o -name '*.ini'  -o -name '*.cfg' \
  -o -name '*.conf' -o -name '*.env'  -o -name '*.example' -o -name '*.go' -o -name '*.py' \
  -o -name '*.rb'   -o -name '*.php'  -o -name '*.c'    -o -name '*.h'    -o -name '*.rs'  \
  -o -name '*.java' -o -name '*.xml'  -o -name '*.svg'  -o -name '*.csv'  -o -name '*.log' \
  -o -name '*.sql'  -o -name 'LICENSE*' -o -name 'Dockerfile*' -o -name '.gitignore'       \
  -o -name 'README*' -o -name 'CONTRIBUTING*' -o -name 'SECURITY*'                          \
\) -exec perl -i -pe '
    s{/Users/[^/\s"]+/Desktop/younger_plinius/03-PLINYOS/organs/t3mp3st}{/work/t3mp3st}g;
    s{younger_plinius/03-PLINYOS/organs/t3mp3st}{t3mp3st}g;
    s{(?:younger_plinius/)?03-PLINYOS/organs/}{}g;   # collapse any sibling-organ nesting
    s{/Users/[^/\s"]+}{/home/user}g;
    # bare macOS username: the owner token in captured ls -l/ps/lsof output
    # (e.g. -rw-r--r-- 1 faber wheel ...). \b word-boundaries avoid mangling
    # substrings; \Q..\E literal-quotes the name so regex metachars stay inert.
    # Boundary = start | escaped-newline (\n as two literal chars in captured ps/lsof
    # transcripts, e.g. "…(LISTEN)\nfaber …") | any NON-alphanumeric incl. underscore
    # (catches the torch cache dir "torchinductor_faber"). \b fails on both. Underscore
    # is a boundary, but a longer ALPHANUMERIC run still protects legit words ('faberge').
    BEGIN { $u = $ENV{USER_TOK} } s{(^|\\[nrt]|[^A-Za-z0-9])\Q$u\E(?![A-Za-z0-9])}{${1}user}g if length $u;
    s{/private/var/folders/[^/]+/[^/]+/}{/tmp/}g;     # macOS per-UID temp-dir hash
    s{/var/folders/[^/]+/[^/]+/}{/tmp/}g;
    s{/private/tmp/}{/tmp/}g;
    s{younger_plinius}{workspace}g;
    s{03-PLINYOS}{workspace}g;
    s{younger-plinius/T3MP3ST}{OWNER/t3mp3st}g;
    s{younger-plinius}{OWNER}g;
  ' {} +
done

# 6) LEAK GATES — fail before doing any expensive build
say "running leak gates…"
fail=0

# Case-SENSITIVE: every forbidden token is fixed-case in the repo. A case-insensitive
# match false-positives on legit lowercase web content (e.g. '/users/' REST paths).
for tok in "${FORBIDDEN[@]}"; do
  hits="$(grep -ral -F "$tok" "$DEST" 2>/dev/null || true)"   # -a: scan binary-classified result JSONs too (NOT -I, which skips them)
  if [[ -n "$hits" ]]; then
    red "GATE FAIL: forbidden token '$tok' survives in:"
    echo "$hits" | sed 's|^|    |'
    fail=1
  fi
done

# Bare macOS username gate — mirrors the scrub's boundary semantics. A plain
# `grep -F "$USER_TOK"` substring-matches innocent words (e.g. 'faberge'); a `-w`/\b
# gate MISSES the "…(LISTEN)\nfaber …" form (escaped-newline → 'n' is a word char). So:
# left boundary = start | escaped \n\r\t | non-word; right boundary = non-word | EOL.
# -a forces text so binary-classified result JSONs are scanned (NOT -I, which skips them).
if [[ -n "$USER_TOK" ]]; then
  hits="$(grep -ralE '(^|[^A-Za-z0-9]|\\[nrt])'"$USER_TOK"'([^A-Za-z0-9]|$)' "$DEST" 2>/dev/null || true)"
  if [[ -n "$hits" ]]; then
    red "GATE FAIL: bare username token '$USER_TOK' survives in:"
    echo "$hits" | sed 's|^|    |'
    fail=1
  fi
fi

for hold in "${HOLDS[@]}"; do
  if [[ -e "$DEST/$hold" ]]; then red "GATE FAIL: hold present in export: $hold"; fail=1; fi
done

# dangling references to the excluded scratch docs (broken-link backstop)
for ex in "${EXCLUDE[@]}"; do
  base="$(basename "$ex")"
  hits="$(grep -ral -F "$base" "$DEST" 2>/dev/null || true)"
  if [[ -n "$hits" ]]; then
    red "GATE FAIL: excluded doc '$base' still referenced in:"
    echo "$hits" | sed 's|^|    |'
    fail=1
  fi
done

if [[ "$fail" -ne 0 ]]; then red "\342\234\227 EXPORT GATES FAILED — not finalizing."; exit 1; fi
grn "\342\234\223 all leak gates passed"

# 7) functional gates inside the export
if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
  say "SKIP_BUILD=1 — running dep-free gates only (verify-claims, test:no-fitting)…"
  ( cd "$DEST" && npm run --silent verify-claims && npm run --silent test:no-fitting )
else
  say "installing + building + testing inside the export…"
  ( cd "$DEST" \
      && npm install --no-audit --no-fund --silent \
      && npm run build \
      && npm test \
      && npm run --silent verify-claims \
      && npm run --silent test:no-fitting )
fi
grn "\342\234\223 functional gates green in the export"

# 8) fresh single-commit history, neutral identity, NO remote, NO push
say "initializing fresh history (single commit, neutral identity, no remote)…"
(
  cd "$DEST"
  rm -rf .git
  git init -q
  git config user.name  "$NEUTRAL_NAME"
  git config user.email "$NEUTRAL_EMAIL"
  git add -A
  git -c commit.gpgsign=false -c user.name="$NEUTRAL_NAME" -c user.email="$NEUTRAL_EMAIL" \
      commit -q -m "t3mp3st — public release"
)

grn "\342\234\223 clean export ready: $DEST"
say "fresh repo, single commit, NO remote, NOT pushed."
say "set package.json repository.url + add your PUBLIC remote, review once more, then push yourself."
