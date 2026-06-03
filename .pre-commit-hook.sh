#!/bin/sh
# env-alert pre-commit hook
# This hook runs env-alert on staged files to detect exposed secrets.
# Install with: env-alert install-hook

echo "🔍 Running env-alert secrets scan..."

# Get staged files that exist (not deleted)
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    echo "  No staged files to scan."
    exit 0
fi

# Run env-alert scan
env-alert scan . --format terminal --no-gitignore 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    # Check error code 2 for high severity findings
    if [ $EXIT_CODE -eq 2 ]; then
        echo ""
        echo "⛔ High-severity secrets detected in staged files!"
        echo "  Please remove or revoke any exposed secrets before committing."
        echo "  To bypass this check (not recommended): git commit --no-verify"
        exit 1
    else
        echo ""
        echo "⚠️  Potential secrets detected in staged files."
        echo "  Review the findings above. If these are false positives,"
        echo "  add them to .env-alert.toml allowlist."
        echo "  To bypass: git commit --no-verify"
        exit 1
    fi
fi

echo "✅ env-alert scan passed - no secrets detected."
exit 0
