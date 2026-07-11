#!/usr/bin/env bash
# Linux / macOS / WSL updater (Windows uses update.ps1 via scripts/update.mjs).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UPSTREAM_URL='https://github.com/elder-plinius/T3MP3ST.git'
UPSTREAM_BRANCH='main'
UPSTREAM_REMOTE='upstream'
DRY_RUN=0
HARD=0
FORCE=0
KEEP_BACKUP=0
STEP_INDEX=0
STEP_TOTAL=0

if [[ -t 1 ]]; then
  C_CYAN=$'\033[36m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_GRAY=$'\033[90m'
  C_WHITE=$'\033[97m'
  C_RESET=$'\033[0m'
else
  C_CYAN='' C_GREEN='' C_YELLOW='' C_GRAY='' C_WHITE='' C_RESET=''
fi

rule() {
  local title="${1:-}"
  local width=68
  echo
  if [[ -n "$title" ]]; then
    local fill=$((width - ${#title} - 4))
    [[ $fill -lt 0 ]] && fill=0
    printf '%s── %s %s%s\n' "$C_CYAN" "$title" "$(printf '─%.0s' $(seq 1 "$fill"))" "$C_RESET"
  else
    printf '%s%s%s\n' "$C_GRAY" "$(printf '─%.0s' $(seq 1 "$width"))" "$C_RESET"
  fi
}

kv() {
  local key="$1" val="$2" color="${3:-$C_WHITE}"
  printf '  %-12s %b%s%b\n' "${key}:" "$color" "$val" "$C_RESET"
}

plan_line() {
  printf '    %s  %s\n' "$1" "$2"
}

start_step() {
  STEP_INDEX=$((STEP_INDEX + 1))
  echo
  if [[ "$STEP_TOTAL" -gt 0 ]]; then
    printf '  %s[%d/%d] %s%s\n' "$C_CYAN" "$STEP_INDEX" "$STEP_TOTAL" "$1" "$C_RESET"
  else
    printf '  [*] %s\n' "$1"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -DryRun|--dry-run) DRY_RUN=1 ;;
    -Hard|--hard) HARD=1 ;;
    -Force|--force) FORCE=1 ;;
    -KeepBackup|--keep-backup) KEEP_BACKUP=1 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

git_install_help() {
  echo '[x] Git is required but was not found on PATH.' >&2
  echo >&2
  case "$(uname -s 2>/dev/null || echo unknown)" in
    Darwin)
      echo 'Install options:' >&2
      echo '  brew install git' >&2
      echo '  xcode-select --install' >&2
      ;;
    Linux|GNU/*)
      echo 'Install with your package manager, for example:' >&2
      echo '  sudo apt install git        # Debian/Ubuntu' >&2
      echo '  sudo dnf install git        # Fedora' >&2
      echo '  sudo pacman -S git          # Arch' >&2
      echo 'More: https://git-scm.com/download/linux' >&2
      ;;
    *)
      echo 'Install Git: https://git-scm.com/downloads' >&2
      ;;
  esac
  echo >&2
  echo 'Then run:  npm run update' >&2
}

npm_install_help() {
  echo '[x] npm is required but was not found on PATH.' >&2
  echo 'Install Node.js (includes npm): https://nodejs.org/' >&2
  echo 'Then run:  npm run update' >&2
}

cd "$ROOT"
[[ -f package.json ]] || { echo '[x] package.json missing' >&2; exit 1; }
command -v git >/dev/null 2>&1 || { git_install_help; exit 1; }
command -v npm >/dev/null 2>&1 || { npm_install_help; exit 1; }

if [[ -f "$ROOT/scripts/update-banner.txt" ]]; then
  cat "$ROOT/scripts/update-banner.txt"
else
  echo 'T3MP3ST'
fi
echo '  T3MP3ST Updater'
echo '  Safe upstream sync - secrets, config, and bench artifacts stay local'
echo

backup="$(mktemp -d -t t3mp3st-update-backup.XXXXXX)"
manifest="$backup/manifest.txt"
: >"$manifest"
protected_count=0
protected_list="$(mktemp)"

on_err() {
  echo >&2
  echo '[x] Update failed partway through.' >&2
  if [[ -f "$manifest" && -s "$manifest" ]]; then
    echo "    Local backup of protected files: $backup" >&2
  fi
}
trap on_err ERR

protect_patterns() {
  grep -v '^#' "$ROOT/scripts/update-protected.txt" | grep -v '^[[:space:]]*$' || true
  [[ -f "$ROOT/scripts/update-protected.local.txt" ]] && grep -v '^#' "$ROOT/scripts/update-protected.local.txt" | grep -v '^[[:space:]]*$' || true
}

path_matches_pattern() {
  local rel="$1" pat="$2"
  pat="${pat//\\//}"
  rel="${rel//\\//}"

  if [[ "$pat" == */ ]]; then
    local prefix="${pat%/}"
    [[ "$rel" == "$prefix" || "$rel" == "$prefix"/* ]]
    return
  fi

  if [[ "$pat" == *[*?]* ]]; then
    case "$rel" in
      $pat) return 0 ;;
    esac
    return 1
  fi

  [[ "$rel" == "$pat" ]]
}

collect_positive_pattern() {
  local pat="$1"
  if [[ "$pat" == */ ]]; then
    local rel="${pat%/}"
    [[ -e "$ROOT/$rel" ]] || return 0
    echo "$rel" >>"$protected_list"
  elif [[ "$pat" == *'*'* ]]; then
    find "$ROOT" -path "$ROOT/$pat" -print 2>/dev/null | while IFS= read -r hit; do
      echo "${hit#"$ROOT/"}" >>"$protected_list"
    done
  else
    [[ -e "$ROOT/$pat" ]] || return 0
    echo "$pat" >>"$protected_list"
  fi
}

apply_negation_patterns() {
  local -a negations=()
  while IFS= read -r pat; do
    [[ "$pat" == !* ]] || continue
    negations+=("${pat:1}")
  done < <(protect_patterns)
  [[ "${#negations[@]}" -eq 0 ]] && return 0

  local filtered
  filtered="$(mktemp)"
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    local skip=0 neg
    for neg in "${negations[@]}"; do
      if path_matches_pattern "$rel" "$neg"; then
        skip=1
        break
      fi
    done
    [[ "$skip" -eq 0 ]] && echo "$rel" >>"$filtered"
  done <"$protected_list"
  mv "$filtered" "$protected_list"
}

collect_protected() {
  while IFS= read -r pat; do
    [[ "$pat" == !* ]] && continue
    collect_positive_pattern "$pat"
  done < <(protect_patterns)
  apply_negation_patterns
}

backup_protected() {
  : >"$manifest"
  while IFS= read -r rel; do
    [[ -n "$rel" && -e "$ROOT/$rel" ]] || continue
    mkdir -p "$backup/$(dirname "$rel")"
    cp -a "$ROOT/$rel" "$backup/$rel"
    echo "$rel" >>"$manifest"
  done <"$protected_list"
}

collect_protected
protected_count="$(grep -c . "$protected_list" 2>/dev/null || echo 0)"
protected_count="$(echo "$protected_count" | tr -d '[:space:]')"
[[ "$protected_count" =~ ^[0-9]+$ ]] || protected_count=0

commit_count="$(git rev-list --count HEAD 2>/dev/null || echo 0)"
[[ -d .git ]] || commit_count=0

strategy='Merge upstream/main'
if [[ "$HARD" -eq 1 ]]; then
  strategy='Hard reset to upstream/main'
elif [[ "$commit_count" -eq 0 ]]; then
  strategy='First-time sync (upstream snapshot)'
fi

platform_label="$(uname -s 2>/dev/null || echo Unix)"
case "$platform_label" in
  Darwin) platform_label='macOS' ;;
  Linux) platform_label='Linux' ;;
esac

rule 'Overview'
kv 'Platform' "$platform_label (bash)" "$C_WHITE"
kv 'Repository' "$ROOT" "$C_WHITE"
kv 'Upstream' "$UPSTREAM_URL @ $UPSTREAM_BRANCH" "$C_WHITE"
kv 'Strategy' "$strategy" "$C_CYAN"
[[ "$DRY_RUN" -eq 1 ]] && kv 'Mode' 'Dry run (preview only)' "$C_YELLOW"

rule 'Protected paths in this repo'
if [[ "$protected_count" -eq 0 ]]; then
  plan_line '-' 'No protected project files in this repo (.env, .keys.*, bench output, etc.)'
else
  while IFS= read -r rel; do
    [[ -n "$rel" ]] && plan_line '+' "$rel"
  done <"$protected_list"
fi

rule 'Never touched (outside repo)'
plan_line '-' '$HOME/.config or AppData t3mp3st config'
plan_line '-' 'War Room browser localStorage'
plan_line '-' 'Codex / Hermes local agent auth'

local_sha='(no commits yet)'
upstream_sha='(unknown)'
if git rev-parse HEAD >/dev/null 2>&1; then
  local_sha="$(git rev-parse --short HEAD 2>/dev/null || echo '(no commits yet)')"
fi
if [[ "$DRY_RUN" -eq 1 ]]; then
  upstream_sha='(preview)'
elif git rev-parse "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH" >/dev/null 2>&1; then
  upstream_sha="$(git rev-parse --short "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH")"
fi

rule 'Revisions'
kv 'Local' "$local_sha" "$C_WHITE"
kv 'Upstream' "$upstream_sha" "$C_CYAN"

plan_steps=()
if [[ "$protected_count" -gt 0 ]]; then
  plan_steps+=("Back up $protected_count protected path(s) to a temp folder")
else
  plan_steps+=('Skip in-repo backup (no protected project files found)')
fi
if [[ ! -d .git ]]; then
  plan_steps+=('Initialize git and add upstream remote')
else
  plan_steps+=('Use existing git repo and upstream remote')
fi
plan_steps+=("Fetch $UPSTREAM_REMOTE/$UPSTREAM_BRANCH")
if [[ "$HARD" -eq 1 ]]; then
  plan_steps+=('Reset working tree to upstream/main')
elif [[ "$commit_count" -eq 0 ]]; then
  plan_steps+=('Apply upstream snapshot to project files')
else
  plan_steps+=('Merge upstream changes into your local branch')
fi
if [[ "$protected_count" -gt 0 ]]; then
  plan_steps+=('Restore backed-up protected paths')
fi
plan_steps+=('Run npm install to refresh dependencies')

rule 'Sync plan'
n=1
for step in "${plan_steps[@]}"; do
  printf '  %2d. %s\n' "$n" "$step"
  n=$((n + 1))
done

if [[ "$FORCE" -eq 0 ]]; then
  echo
  printf 'Proceed with update? [y/N] '
  read -r ans
  [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]] || { echo '[!] Cancelled - no changes made.'; rm -rf "$backup"; trap - ERR; exit 0; }
fi

STEP_TOTAL=2
[[ "$protected_count" -gt 0 ]] && STEP_TOTAL=$((STEP_TOTAL + 2))
STEP_INDEX=0

if [[ "$protected_count" -gt 0 ]]; then
  start_step 'Backing up protected files'
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo '  [*] [dry-run] would back up protected paths'
  else
    backup_protected
    printf '  [+] Backed up %d path(s)\n' "$protected_count"
  fi
fi

start_step 'Syncing from upstream'
if [[ "$DRY_RUN" -eq 1 ]]; then
  [[ -d .git ]] || echo '  [*] [dry-run] would run: git init'
  if [[ -d .git ]] && ! git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
    echo "  [*] [dry-run] would run: git remote add $UPSTREAM_REMOTE $UPSTREAM_URL"
  fi
  echo "  [*] [dry-run] would run: git fetch $UPSTREAM_REMOTE $UPSTREAM_BRANCH"
  if [[ "$HARD" -eq 1 ]]; then
    echo "  [*] [dry-run] would run: git reset --hard $UPSTREAM_REMOTE/$UPSTREAM_BRANCH"
  elif [[ "$commit_count" -eq 0 ]]; then
    echo '  [*] [dry-run] would apply upstream snapshot (checkout upstream/main)'
    echo "  [*] [dry-run] would run: git checkout -B $UPSTREAM_BRANCH $UPSTREAM_REMOTE/$UPSTREAM_BRANCH"
  else
    echo "  [*] [dry-run] would run: git merge $UPSTREAM_REMOTE/$UPSTREAM_BRANCH"
  fi
else
  [[ -d .git ]] || git init
  git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1 || git remote add "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
  git fetch "$UPSTREAM_REMOTE" "$UPSTREAM_BRANCH" 2>&1 || true

  if [[ "$HARD" -eq 1 ]]; then
    git reset --hard "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH"
  elif [[ "$commit_count" -eq 0 ]]; then
    find "$ROOT" -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +
    git checkout -B "$UPSTREAM_BRANCH" "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH"
  else
    git merge "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH" --no-edit
  fi
  echo '  [+] Git sync finished'
fi

if [[ "$protected_count" -gt 0 ]]; then
  start_step 'Restoring protected files'
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo '  [*] [dry-run] would restore protected paths'
  else
    while IFS= read -r rel; do
      [[ -n "$rel" && -e "$backup/$rel" ]] || continue
      mkdir -p "$(dirname "$ROOT/$rel")"
      rm -rf "$ROOT/$rel"
      cp -a "$backup/$rel" "$ROOT/$rel"
    done <"$manifest"
    echo '  [+] Protected paths restored'
  fi
fi

start_step 'Refreshing npm packages'
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo '  [*] [dry-run] would run: npm install'
else
  npm install
  echo '  [+] npm install finished'
fi

new_sha="$upstream_sha"
if [[ "$DRY_RUN" -eq 0 ]] && git rev-parse HEAD >/dev/null 2>&1; then
  new_sha="$(git rev-parse --short HEAD)"
fi

rule 'Done'
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo '  Preview only - no files were changed.'
  echo '  Run without --dry-run when you are ready.'
else
  echo '  Update complete'
  kv 'Before' "$local_sha" "$C_WHITE"
  kv 'After' "$new_sha" "$C_GREEN"
fi
echo

trap - ERR
[[ "$KEEP_BACKUP" -eq 1 ]] || rm -rf "$backup"
