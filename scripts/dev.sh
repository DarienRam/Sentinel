#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
backend_venv="$project_root/backend/.venv/bin/activate"

if [[ ! -f "$backend_venv" ]]; then
  echo "Missing backend virtual environment at backend/.venv. Run: bash scripts/setup.sh"
  exit 1
fi

if [[ ! -d "$project_root/frontend/node_modules" ]]; then
  echo "Missing frontend dependencies. Run: bash scripts/setup.sh"
  exit 1
fi

cleanup() {
  trap - EXIT INT TERM
  kill "$backend_pid" "$frontend_pid" 2>/dev/null || true
}

(
  cd "$project_root/backend"
  source "$backend_venv"
  exec uvicorn app.main:app --reload --no-proxy-headers
) &
backend_pid=$!

(
  cd "$project_root/frontend"
  exec npm run dev
) &
frontend_pid=$!

trap cleanup EXIT INT TERM

echo "Starting Sentinel at http://localhost:3000"
echo "Press Ctrl+C once to stop both the frontend and backend."

wait "$backend_pid" "$frontend_pid"
