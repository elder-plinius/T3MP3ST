#!/usr/bin/env bash
# T3MP3ST key vault — tiny macOS Keychain wrapper for LLM / agent secrets.
#
# Zero-install: uses the built-in `security` command. Encrypted at rest by
# macOS login keychain (unlocked when you're logged in).
#
# Usage:
#   ./scripts/keys.sh set    KEYNAME      # store key (hidden prompt)
#   ./scripts/keys.sh get    KEYNAME      # print key value
#   ./scripts/keys.sh load                # print export statements for known keys
#                                         # use:  eval "$(./scripts/keys.sh load)"
#   ./scripts/keys.sh list                # show which known keys are set
#   ./scripts/keys.sh unset  KEYNAME      # delete key
#   ./scripts/keys.sh exec   <cmd...>     # run a command with known keys exported
#
# Examples:
#   ./scripts/keys.sh set OPENROUTER_API_KEY
#   ./scripts/keys.sh list
#   ./scripts/keys.sh exec npm run cve:bench:live

set -euo pipefail

SERVICE="t3mp3st-bench-keys"

# Curated list of well-known keys the bench / agents read.
# Add more here as you start using new providers.
KNOWN_KEYS=(
  OPENROUTER_API_KEY
  ANTHROPIC_API_KEY
  OPENAI_API_KEY
  GROQ_API_KEY
  TOGETHER_API_KEY
  HUGGINGFACE_TOKEN
  REPLICATE_API_TOKEN
  GITHUB_TOKEN
  HF_TOKEN
)

# ---- helpers ---------------------------------------------------------------

require_macos() {
  if [ "$(uname)" != "Darwin" ]; then
    echo "keys.sh: requires macOS (uses the native security command)" >&2
    exit 2
  fi
}

require_arg() {
  if [ -z "${1:-}" ]; then
    echo "usage: $0 $2 KEYNAME" >&2
    exit 2
  fi
}

keychain_get() {
  security find-generic-password -a "$1" -s "$SERVICE" -w 2>/dev/null || true
}

keychain_set() {
  security add-generic-password -a "$1" -s "$SERVICE" -w "$2" -U >/dev/null
}

keychain_del() {
  security delete-generic-password -a "$1" -s "$SERVICE" >/dev/null 2>&1
}

# ---- commands --------------------------------------------------------------

cmd_set() {
  require_arg "${1:-}" "set"
  local name="$1"
  printf "Enter value for %s (input hidden): " "$name" >&2
  local value
  IFS= read -rs value
  printf "\n" >&2
  if [ -z "$value" ]; then
    echo "(empty value — aborting, nothing changed)" >&2
    exit 2
  fi
  keychain_set "$name" "$value"
  echo "✓ stored $name in macOS Keychain (service=$SERVICE)" >&2
}

cmd_get() {
  require_arg "${1:-}" "get"
  local v
  v="$(keychain_get "$1")"
  if [ -z "$v" ]; then
    echo "$1: not set" >&2
    exit 1
  fi
  printf "%s" "$v"
}

cmd_load() {
  for name in "${KNOWN_KEYS[@]}"; do
    v="$(keychain_get "$name")"
    if [ -n "$v" ]; then
      # shell-escape via single-quote-wrap, escaping inner single quotes
      esc="${v//\'/\'\\\'\'}"
      printf "export %s='%s'\n" "$name" "$esc"
    fi
  done
}

cmd_list() {
  echo "Known keys (service=$SERVICE):"
  local any=0
  for name in "${KNOWN_KEYS[@]}"; do
    v="$(keychain_get "$name")"
    if [ -n "$v" ]; then
      printf "  ✓ %-24s set (length=%d)\n" "$name" "${#v}"
      any=1
    else
      printf "  · %-24s unset\n" "$name"
    fi
  done
  if [ "$any" -eq 0 ]; then
    echo ""
    echo "  (no keys stored yet — try:  $0 set OPENROUTER_API_KEY )" >&2
  fi
}

cmd_unset() {
  require_arg "${1:-}" "unset"
  if keychain_del "$1"; then
    echo "✓ deleted $1" >&2
  else
    echo "✗ $1 not found" >&2
    exit 1
  fi
}

cmd_exec() {
  if [ "$#" -eq 0 ]; then
    echo "usage: $0 exec <command> [args...]" >&2
    exit 2
  fi
  # Export all known keys that are set, then exec the command.
  for name in "${KNOWN_KEYS[@]}"; do
    v="$(keychain_get "$name")"
    [ -n "$v" ] && export "$name"="$v"
  done
  exec "$@"
}

cmd_help() {
  cat >&2 <<EOF
T3MP3ST key vault (macOS Keychain, service="$SERVICE")

  $0 set    KEYNAME            store a key (hidden prompt)
  $0 get    KEYNAME            print key value to stdout
  $0 unset  KEYNAME            delete a key
  $0 list                      show which known keys are set
  $0 load                      print export statements
                                 use: eval "\$($0 load)"
  $0 exec   <cmd> [args...]    run cmd with all known keys exported

Known keys this vault tracks:
$(printf "  %s\n" "${KNOWN_KEYS[@]}")

Add more keys to the KNOWN_KEYS list inside this script as needed.
EOF
}

# ---- dispatch --------------------------------------------------------------

require_macos
cmd="${1:-help}"; shift || true

case "$cmd" in
  set)    cmd_set    "$@" ;;
  get)    cmd_get    "$@" ;;
  unset)  cmd_unset  "$@" ;;
  list)   cmd_list ;;
  load)   cmd_load ;;
  exec)   cmd_exec   "$@" ;;
  -h|--help|help) cmd_help ;;
  *)
    echo "unknown command: $cmd" >&2
    cmd_help
    exit 2
    ;;
esac
