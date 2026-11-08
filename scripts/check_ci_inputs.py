"""Strict public-source allowlist and complete reachable-history data/secret gate."""
import argparse
import re
import subprocess
from pathlib import Path

ALLOWED = frozenset({'backend/app/tests/test_scan_api.py', 'frontend/eslint.config.mjs', 'frontend/app/dashboard/page.tsx', 'backend/.env.example', 'backend/app/tests/test_scan_persistence.py', 'backend/app/core/config.py', 'backend/app/models/user.py', 'frontend/components/auth-provider.tsx', 'backend/app/main.py', '.nvmrc', 'backend/app/schemas/auth.py', 'docs/screenshots/01-landing-page.png', 'backend/app/tests/test_scan_engine.py', '.python-version', 'docs/screenshots/04-dashboard.png', 'backend/requirements-redis.txt', 'scripts/check_ci_inputs.py', 'frontend/app/page.tsx', 'frontend/scripts/test-api.mjs', 'frontend/README.md', 'backend/app/tests/test_auth_api.py', 'docs/api-contract.md', 'README.md', 'backend/app/tests/test_anonymous_security.py', 'docs/screenshots/05-safety-guide.png', 'frontend/tsconfig.json', 'backend/app/tests/conftest.py', 'backend/alembic.ini', 'backend/app/core/security.py', 'backend/app/models/__init__.py', 'backend/app/tests/test_hostile_inputs.py', 'backend/app/core/account_sessions.py', 'frontend/package-lock.json', 'backend/migrations/versions/0001_baseline.py', 'backend/migrations/versions/0002_query_indexes.py', 'backend/app/tests/test_database_safety.py', 'frontend/app/scans/[id]/page.module.css', 'backend/app/models/scan.py', 'frontend/next.config.mjs', 'frontend/.env.local.example', 'frontend/app/analyze/page.module.css', 'docs/screenshots/03-scan-report.png', 'frontend/package.json', 'backend/app/api/scans.py', 'backend/app/tests/test_url_security.py', 'backend/requirements-dev.txt', 'backend/app/core/resource_protection.py', 'backend/app/api/auth.py', 'backend/app/core/security_store.py', 'frontend/lib/api.ts', 'backend/app/tests/test_resource_protection.py', 'frontend/app/analyze/page.tsx', 'SECURITY.md', 'frontend/next-env.d.ts', 'docs/architecture.md', 'backend/app/tests/test_v1_release_boundary.py', 'backend/app/services/retention.py', 'frontend/app/route-shell.module.css', 'frontend/app/globals.css', 'docs/screenshots/02-analyze-high-risk.png', 'frontend/app/scans/[id]/page.tsx', 'frontend/components/site-header.tsx', 'backend/app/api/__init__.py', 'frontend/app/learn/page.tsx', 'backend/app/services/scan_engine.py', 'backend/app/api/anonymous.py', 'backend/app/tests/test_password_security.py', 'backend/app/core/database.py', 'backend/app/services/__init__.py', 'backend/app/core/response_headers.py', 'backend/app/schemas/__init__.py', 'backend/app/core/url_validation.py', 'backend/requirements.txt', 'backend/requirements.lock', 'backend/app/retention.py', 'backend/app/schemas/scan.py', 'frontend/app/register/page.tsx', 'frontend/app/layout.tsx', 'docs/screenshots/README.md', 'frontend/app/login/page.tsx', 'scripts/setup.sh', 'backend/app/tests/test_security_config.py', 'backend/migrations/env.py', 'backend/app/core/anonymous_sessions.py', 'backend/app/tests/test_account_lifecycle.py', 'frontend/app/learn/page.module.css', '.gitignore', 'docs/attribution.md', 'frontend/app/dashboard/page.module.css', 'scripts/dev.sh', 'frontend/app/page.module.css', '.github/workflows/security-ci.yml'})
FORBIDDEN_MAGICS=(b'SQLite format 3\0',b'PK\x03\x04',b'\x1f\x8b',b'BZh')
TOKEN_PATTERNS=[rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
                rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
                rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b',
                rb'\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b']


def validate_blob(name,data):
    if name not in ALLOWED:
        raise ValueError('Path outside approved public manifest: '+name)
    if len(data)>8*1024**2 or data.startswith(FORBIDDEN_MAGICS):
        raise ValueError('Data/archive/binary boundary violation: '+name)
    if name.endswith('.png'):
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):
            raise ValueError('Invalid screenshot format: '+name)
        return
    if b'\0' in data:
        raise ValueError('Unexpected binary file: '+name)
    if any(re.search(pattern,data) for pattern in TOKEN_PATTERNS):
        raise ValueError('Credential-like content found (value suppressed): '+name)
    if re.search(rb'(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?)://[^\s/]+:[^\s/@]+@',data) and '/tests/' not in name:
        raise ValueError('Embedded service credential (value suppressed): '+name)


def git(*args):
    return subprocess.check_output(['git','--no-optional-locks',*args],stderr=subprocess.DEVNULL)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--history',action='store_true');args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    if Path.cwd().resolve()!=root:
        raise SystemExit('Run this checker from the repository root.')
    for folder in ('ml','backend/private-data','backend/model-artifacts'):
        if (root/folder).exists():raise SystemExit('Forbidden private directory present: '+folder)
    for p in [root/'backend/.env',root/'frontend/.env.local',*list((root/'backend').glob('*.db'))]:
        if p.exists():raise SystemExit('Private runtime file present (content suppressed).')
    try:
        names=[n.decode() for n in git('ls-files','--cached','--others','--exclude-standard','-z').split(b'\0') if n]
    except subprocess.CalledProcessError:
        names=list(ALLOWED)
    checked=0
    for name in names:
        p=root/name
        if p.is_symlink():raise SystemExit('Symlink not permitted: '+name)
        if p.is_file():validate_blob(name,p.read_bytes());checked+=1
    commits=[];objects=set()
    if args.history:
        try:commits=git('rev-list','--all').decode().splitlines()
        except subprocess.CalledProcessError:commits=[]
        for commit in commits:
            for entry in git('ls-tree','-r','-z',commit).split(b'\0'):
                if not entry:continue
                metadata,path=entry.split(b'\t',1);mode,kind,sha=metadata.decode().split();name=path.decode()
                if kind!='blob' or mode=='120000':raise SystemExit('Non-regular historical source entry.')
                pair=(sha,name)
                if pair not in objects:
                    validate_blob(name,git('cat-file','blob',sha));objects.add(pair)
    print(f'Public boundary passed: {checked} source files, {len(commits)} commits, {len(objects)} historical path/blob pairs.')
    if args.history and not commits:print('No commits exist. Repeat the full-history gate after any future approved commits and before visibility changes.')


if __name__=='__main__':
    try:main()
    except ValueError as exc:raise SystemExit(str(exc)) from None
