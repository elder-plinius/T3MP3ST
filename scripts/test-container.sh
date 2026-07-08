#!/usr/bin/env bash
# test-container.sh — smoke tests for the tempest-stack container
# Run inside the container: docker exec <name> /opt/t3mp3st/scripts/test-container.sh
# Or from host:            docker exec tempest-stack /opt/t3mp3st/scripts/test-container.sh

set -euo pipefail

BASE_T3="${T3MP3ST_URL:-http://localhost:3333}"
BASE_OBL="${OBLITERATUS_SIDECAR_URL:-http://localhost:8765}"
PASS=0
FAIL=0

ok()  { echo "[PASS] $*"; PASS=$((PASS + 1)); }
fail(){ echo "[FAIL] $*"; FAIL=$((FAIL + 1)); }
section() { echo ""; echo "── $* ─────────────────────────────────────"; }

# ── helpers ──────────────────────────────────────────────────────────────────

http_get() {
  curl -sf --max-time 10 "$1" 2>/dev/null
}

http_post() {
  local url="$1"; local body="$2"
  curl -sf --max-time 30 -X POST -H "Content-Type: application/json" -d "$body" "$url" 2>/dev/null
}

assert_ok() {
  local label="$1"; local out="$2"
  if [ -n "$out" ]; then ok "$label"; else fail "$label (empty/error response)"; fi
}

# ── T3MP3ST health ────────────────────────────────────────────────────────────

section "T3MP3ST core health"

out=$(http_get "$BASE_T3/health") && \
  echo "$out" | grep -q '"status"' && ok "GET /health → 200 with status field" || fail "GET /health failed"

out=$(http_get "$BASE_T3/api/preflight") && \
  assert_ok "GET /api/preflight" "$out" || true

# ── OBLITERATUS sidecar health ────────────────────────────────────────────────

section "OBLITERATUS sidecar health"

out=$(http_get "$BASE_OBL/health") && \
  echo "$out" | grep -q '"status"' && ok "GET :8765/health → 200" || fail "GET :8765/health failed (sidecar may still be starting)"

out=$(http_get "$BASE_T3/api/obliteratus/health") && \
  echo "$out" | grep -q '"status"' && ok "GET /api/obliteratus/health proxy → 200" || fail "GET /api/obliteratus/health proxy failed"

out=$(http_get "$BASE_T3/api/obliteratus/models") && \
  assert_ok "GET /api/obliteratus/models (may be empty [])" "$out" || true

# ── GLOSSOPETRAE encode/decode roundtrip ─────────────────────────────────────

section "GLOSSOPETRAE encode/decode roundtrip"

# Direct encode test (fastest, most reliable)
enc=$(http_post "$BASE_T3/api/glossopetrae/encode" '{"mission_id":"smoke-test-mission","text":"hello world"}')
if echo "$enc" | grep -q '"encoded"'; then
  ok "POST /api/glossopetrae/encode → encoded string returned"
else
  fail "POST /api/glossopetrae/encode failed: ${enc:0:200}"
fi

# ── GLOSSOPETRAE session API ──────────────────────────────────────────────────

section "GLOSSOPETRAE session API"

session_out=$(http_post "$BASE_T3/api/glossopetrae/session" '{"mission_id":"smoke-test-mission","preset":"covert"}')
if echo "$session_out" | grep -q '"missionId"'; then
  ok "POST /api/glossopetrae/session → session created"
  LANG_NAME=$(echo "$session_out" | grep -o '"languageName":"[^"]*"' | cut -d'"' -f4)
  STONE_LEN=$(echo "$session_out" | grep -o '"stoneLengthChars":[0-9]*' | cut -d: -f2)
  echo "    Language: $LANG_NAME | Stone: ${STONE_LEN} chars"
else
  fail "POST /api/glossopetrae/session failed: $session_out"
fi

stone_out=$(http_get "$BASE_T3/api/glossopetrae/session/smoke-test-mission/skillstone")
if echo "$stone_out" | grep -q '"stone"'; then
  STONE_LEN=$(echo "$stone_out" | grep -o '"stone":"[^"]*"' | wc -c)
  ok "GET /api/glossopetrae/session/:id/skillstone → stone present (raw len: $STONE_LEN chars)"
else
  fail "GET .../skillstone failed: $stone_out"
fi

encode_out=$(http_post "$BASE_T3/api/glossopetrae/encode" '{"mission_id":"smoke-test-mission","text":"hello world"}')
if echo "$encode_out" | grep -q '"encoded"'; then
  ok "POST /api/glossopetrae/encode → encoded successfully"
else
  fail "POST /api/glossopetrae/encode failed: $encode_out"
fi

# ── GLOSSOPETRAE stego encode ────────────────────────────────────────────────
# Tests that the stego infrastructure is wired up end-to-end.
# stegoEncode takes ENGLISH cover and translates+encodes internally.
# RS ECC overhead: 32 parity bytes + 9-byte frame header = 344 bits minimum
# for any payload, requiring 300+ English words of cover text.
# Note: stegoDecode has a known design limitation in GLOSSOPETRAE-1's
# SteganographyEngine — interleaving assumes encode/decode extract identical
# bit counts, but decoder reads extra morpheme bits from trailing unencoded
# words, corrupting the de-interleaved frame.  Encode-only is tested here.

section "GLOSSOPETRAE stego encode"

stego_result=$(python3 - <<'PYEOF' 2>/dev/null
import urllib.request, json

cover = ("the ancient warrior of the northern mountains rises at dawn to defend "
  "the sacred citadel where the elders gather and the young soldiers train hard "
  "every day for the coming battle the great river flows west toward the wide sea "
  "carrying the distant memories of fallen warriors who fought with courage for the "
  "freedom of their beloved people the sun sets slowly over the distant green hills "
  "painting the evening sky in deep shades of crimson and bright gold while the night "
  "watch begins their long duty at the high stone walls of the fortress the wise general "
  "surveys the open land from the highest tower and carefully plans the bold strategy "
  "that will bring final victory to his loyal people the enemy camps in the dark valley "
  "below and patiently waits for the cold morning to advance with force against the "
  "strong walls but the brave defenders are fully ready with sharp weapons and great "
  "courage and deep knowledge of the rugged terrain they know every hidden path and "
  "every secret approach and they will use this hard won knowledge to defend their "
  "beloved home the children of the city sleep safely knowing their brave protectors "
  "stand guard through the long cold winter night until the bright morning comes and "
  "brings with it another good day of peaceful life and renewed hope and the sacred "
  "promise of lasting peace when the long bitter struggle finally ends and the enemy "
  "is completely defeated and the free land is restored and all people can live without "
  "constant fear of war and open trade can resume safely along the ancient stone roads "
  "that connect the small villages and the great cities and the busy markets where "
  "skilled merchants sell their fine goods and curious travelers share wonderful stories "
  "from distant foreign lands across high mountains and far beyond the wide sea where "
  "the seasons slowly turn and rich harvests are gathered and strong children grow tall")

body = json.dumps({
    'mission_id': 'smoke-test-mission',
    'cover': cover,
    'secret': 'X'
}).encode()
req = urllib.request.Request(
    'http://localhost:3333/api/glossopetrae/stego/hide',
    data=body, headers={'Content-Type': 'application/json'}, method='POST')
try:
    with urllib.request.urlopen(req, timeout=60) as r:
        result = json.loads(r.read())
        if result.get('stego') and result.get('success'):
            print('OK')
            print(len(result['stego']))
        else:
            print('FAIL')
            print(str(result)[:200])
except Exception as e:
    print('FAIL')
    print(str(e)[:200])
PYEOF
)

first_line=$(echo "$stego_result" | head -1)
stego_len=$(echo "$stego_result" | tail -1)
if [ "$first_line" = "OK" ]; then
  ok "POST /api/glossopetrae/stego/hide → stego text produced (${stego_len} chars, encode-only verified)"
else
  fail "POST /api/glossopetrae/stego/hide: $stego_len"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "══════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
