#!/usr/bin/env bash
set -euo pipefail

API_URL=''; API_ID=''; API_KEY=''; REPOSITORY=''; BRANCH=''; COMMIT=''; OUTPUT=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url) API_URL="$2"; shift 2;;
    --api-id) API_ID="$2"; shift 2;;
    --api-key) API_KEY="$2"; shift 2;;
    --repository) REPOSITORY="$2"; shift 2;;
    --branch) BRANCH="$2"; shift 2;;
    --commit) COMMIT="$2"; shift 2;;
    --output) OUTPUT="$2"; shift 2;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done

mkdir -p "$(dirname "$OUTPUT")"

# INTEGRATION POINT:
# Replace the block below with the real command/API for your ACM product.
# The final file MUST be JSON in this normalized form:
# {"findings":[{"id":"...","severity":"CRITICAL|HIGH|MEDIUM|LOW","title":"..."}]}
# Never echo API_KEY.

echo "ACM scanner adapter has not yet been configured for your ACM product." >&2
echo "Edit scripts/run-acm-scan.sh and replace the integration block with the vendor CLI/API." >&2
exit 10
