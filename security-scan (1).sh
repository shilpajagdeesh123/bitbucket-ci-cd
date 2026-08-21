#!/bin/sh

set -eu

echo "========================================"
echo " Bitbucket Repository Security Scan"
echo "========================================"

FAILED=0

# Scan only tracked repository files and ignore binary content.
# This avoids scanning .git, build output, node_modules, etc. unless they are committed.
check_pattern() {
    NAME="$1"
    PATTERN="$2"

    echo ""
    echo "Checking: $NAME"

    MATCHES=$(git grep -IEn "$PATTERN" -- . \
        ':(exclude).security/security-scan.sh' \
        ':(exclude)bitbucket-pipelines.yml' 2>/dev/null || true)

    if [ -n "$MATCHES" ]; then
        echo "SECURITY VIOLATION: $NAME detected"
        echo "$MATCHES"
        FAILED=1
    else
        echo "PASS: No $NAME detected"
    fi
}

# 1. Passwords
check_pattern \
"hard-coded password" \
'(password|passwd|pwd)[[:space:]]*[:=][[:space:]]*["'\''`]?[A-Za-z0-9@#$%^&*._!+=:/?-]{4,}'

# 2. Tokens
check_pattern \
"hard-coded token" \
'(token|access_token|access-token|auth_token|auth-token|bearer_token|bearer-token)[[:space:]]*[:=][[:space:]]*["'\''`]?[A-Za-z0-9._~+/-]{8,}'

# 3. API keys
check_pattern \
"API key" \
'(api_key|api-key|apikey)[[:space:]]*[:=][[:space:]]*["'\''`]?[A-Za-z0-9._~+/-]{8,}'

# 4. Client secrets / secret keys
check_pattern \
"secret" \
'(client_secret|client-secret|secret_key|secret-key|clientsecret)[[:space:]]*[:=][[:space:]]*["'\''`]?[A-Za-z0-9._~+/-]{8,}'

# 5. Common private key markers
check_pattern \
"private key" \
'-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'

# 6. Email addresses
check_pattern \
"email address" \
'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'

echo ""
echo "========================================"

if [ "$FAILED" -ne 0 ]; then
    echo "SECURITY SCAN FAILED"
    echo "Pipeline will be stopped."
    echo "Remove the sensitive value and push again."
    echo "========================================"
    exit 1
fi

echo "SECURITY SCAN PASSED"
echo "========================================"
exit 0
