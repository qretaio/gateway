#!/bin/sh
# Secret scan for the gateway repo. Used by the pre-commit hook and runnable
# by hand:  scripts/gitleaks-scan.sh [ --staged ]
#
# --staged scans only the files staged for commit (fast, the pre-commit
# path). Without it, the full git history + working tree is scanned.
set -eu

# Resolve from git rather than $0: some harnesses wrap $0 with extra
# path text. `git rev-parse` always names the real checkout root.
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

if ! command -v gitleaks >/dev/null 2>&1; then
    echo "[gitleaks] not installed — install with: brew install gitleaks" >&2
    echo "[gitleaks] see https://github.com/gitleaks/gitleaks" >&2
    exit 1
fi

MODE=${1:-}
if [ "$MODE" = "--staged" ]; then
    # Scan the staged diff against the configured rules. `git diff
    # --cached --name-only --diff-filter=ACM` lists added/copied/modified
    # files; deleted files cannot introduce a secret.
    files=$(git diff --cached --name-only --diff-filter=ACM)
    if [ -z "$files" ]; then
        exit 0
    fi
    echo "$files" | while IFS= read -r f; do
        # Skip paths removed from the index between listing and scan.
        [ -f "$f" ] || continue
        gitleaks --config .gitleaks.toml --no-banner --redact dir "$f" >/dev/null
    done
else
    gitleaks --config .gitleaks.toml --no-banner --redact detect
fi
