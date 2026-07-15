#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- venv ---
if [ ! -d ".venv" ]; then
  echo "[aegispam] creating venv..."
  python3 -m venv .venv
fi

source .venv/bin/activate

# --- deps ---
echo "[aegispam] installing dependencies..."
# shap's optional numba dep doesn't support Python 3.14 — pre-install without it
pip install -q --no-deps shap==0.52.0
pip install -q -r requirements.txt

# --- env ---
if [ -f .env ]; then
  set -a; source .env; set +a
fi

CBS_PORT="${CBS_PORT:-8001}"
API_PORT="${API_PORT:-8000}"

cleanup() {
  echo ""
  echo "[aegispam] shutting down..."
  kill "$CBS_PID" "$API_PID" 2>/dev/null || true
  # dashboard is launched only when dashboard.py exists
  [ -n "${DASH_PID:-}" ] && kill "$DASH_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --- mock CBS (port 8001) ---
echo "[aegispam] starting Mock CBS on :$CBS_PORT"
uvicorn mock_cbs:app --host 0.0.0.0 --port "$CBS_PORT" --log-level warning &
CBS_PID=$!

# --- control API (port 8000) ---
echo "[aegispam] starting Control API on :$API_PORT"
uvicorn main:app --host 0.0.0.0 --port "$API_PORT" --log-level warning &
API_PID=$!

# --- wait for API to be ready ---
echo "[aegispam] waiting for API on :$API_PORT..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:$API_PORT/health" >/dev/null 2>&1 || \
     curl -sf "http://localhost:$API_PORT/docs" >/dev/null 2>&1; then
    echo "[aegispam] API is ready."
    break
  fi
  sleep 1
done

# --- dashboard (port 8501) — launched only once dashboard.py is implemented ---
if [ -f dashboard.py ]; then
  echo "[aegispam] starting Dashboard on :8501"
  streamlit run dashboard.py --server.port 8501 --server.headless true &
  DASH_PID=$!
fi

echo ""
echo "┌─────────────────────────────────────────┐"
echo "│           AegisPAM is running            │"
echo "├─────────────────────────────────────────┤"
echo "│  Control API  →  http://localhost:$API_PORT   │"
echo "│  API Docs     →  http://localhost:$API_PORT/docs │"
echo "│  Mock CBS     →  http://localhost:$CBS_PORT   │"
[ -f dashboard.py ] && echo "│  Dashboard    →  http://localhost:8501   │"
echo "└─────────────────────────────────────────┘"
echo ""
echo "Press Ctrl+C to stop all services."

wait
