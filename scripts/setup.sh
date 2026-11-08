#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${PYTHON_BIN:-python3.13}"
if ! command -v "$python_bin" >/dev/null || ! command -v node >/dev/null || ! command -v npm >/dev/null; then
  echo "Install the Python and Node versions in .python-version and .nvmrc first." >&2
  exit 1
fi
"$python_bin" - "$project_root/.python-version" <<'CHECKPY'
import pathlib,sys
minimum=tuple(map(int,pathlib.Path(sys.argv[1]).read_text().strip().split('.')))
if sys.version_info[:2] != minimum[:2] or sys.version_info[:3] < minimum:
    raise SystemExit('Use the supported Python patch version in .python-version or a newer patch in that minor series.')
CHECKPY
node - "$project_root/.nvmrc" <<'CHECKNODE'
const fs = require('node:fs');
const minimum = fs.readFileSync(process.argv[2], 'utf8').trim().replace(/^v/, '').split('.').map(Number);
const actual = process.versions.node.split('.').map(Number);
if (actual[0] !== minimum[0] || actual[1] < minimum[1] || (actual[1] === minimum[1] && actual[2] < minimum[2])) {
  throw new Error('Use the Node version in .nvmrc or a newer patch/minor in that LTS major.');
}
CHECKNODE
"$python_bin" -m venv "$project_root/backend/.venv"
(
  cd "$project_root/backend"
  .venv/bin/python -m pip install --require-hashes -r requirements.lock
  .venv/bin/python -m pip check
)
(
  cd "$project_root/frontend"
  npm ci --ignore-scripts
)
echo "Setup complete. Start Sentinel with: bash scripts/dev.sh"
