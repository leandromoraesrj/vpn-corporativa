#!/bin/bash
set -euo pipefail
export LC_ALL=C.UTF-8
export PYTHONDONTWRITEBYTECODE=1
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

cleanup() {
    find "$ROOT" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
    find "$ROOT" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete 2>/dev/null || true
}
trap cleanup EXIT
cleanup

printf '== Validação VPN Corporativa 1.0 — Produção ==\n'
python3 - <<'PY'
import ast
from pathlib import Path
root = Path('.')
files = [root / 'vpn.py', *sorted((root / 'vpn_app').glob('*.py')), *sorted((root / 'tests').glob('test_*.py'))]
for path in files:
    ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
print(f'AST: {len(files)} arquivo(s) Python válidos')
PY
for script in install.sh uninstall.sh auditar_vpn.sh vpn-connect vpn-disconnect vpn-diagnose vpn-process-identity validate_release.sh; do
    bash -n "$script"
done
printf 'Shell: sintaxe válida\n'
python3 -m unittest discover -s tests -v
printf 'Release validada com sucesso.\n'
