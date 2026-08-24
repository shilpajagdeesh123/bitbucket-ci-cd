#!/usr/bin/env bash
set -u

FAILED=0
ALLOW_EMAIL_REGEX="${ALLOW_EMAIL_REGEX:-}"

report() {
  category="$1"; commit="$2"; path="$3"; line_no="$4"; message="$5"
  echo "remote: [SECURITY] ${category} detected"
  echo "remote:   Commit: ${commit}"
  echo "remote:   File:   ${path}"
  echo "remote:   Line:   ${line_no}"
  echo "remote:   Detail: ${message}"
  echo "remote:"
  FAILED=1
}

scan_blob() {
  commit="$1"; path="$2"

  if ! git cat-file -e "${commit}:${path}" 2>/dev/null; then
    return 0
  fi

  size="$(git cat-file -s "${commit}:${path}" 2>/dev/null || echo 0)"
  case "$size" in ''|*[!0-9]*) size=0 ;; esac
  if [ "$size" -gt 2097152 ]; then
    echo "remote: [SECURITY] Skipping large file (>2 MiB): ${path}"
    return 0
  fi

  tmp="$(mktemp)"
  if ! git show "${commit}:${path}" >"$tmp" 2>/dev/null; then
    rm -f "$tmp"
    return 0
  fi

  if ! LC_ALL=C grep -Iq . "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    return 0
  fi

  line_no=0
  while IFS= read -r line || [ -n "$line" ]; do
    line_no=$((line_no + 1))

    case "$line" in *"security-scan: allow"*) continue ;; esac

    if printf '%s\n' "$line" | grep -Eiq '(password|passwd|pwd)[[:space:]]*[:=][[:space:]]*["'"'"']?[^[:space:]"'"'"']{4,}'; then
      report "Hard-coded password" "$commit" "$path" "$line_no" "Password-like assignment found"
    fi

    if printf '%s\n' "$line" | grep -Eiq '(access[_-]?token|auth[_-]?token|bearer[_-]?token|refresh[_-]?token|token)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._~+/=-]{8,}'; then
      report "Hard-coded token" "$commit" "$path" "$line_no" "Token-like assignment found"
    fi

    if printf '%s\n' "$line" | grep -Eiq '(api[_-]?key|apikey)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._~+/=-]{8,}'; then
      report "API key" "$commit" "$path" "$line_no" "API-key-like assignment found"
    fi

    if printf '%s\n' "$line" | grep -Eiq '(client[_-]?secret|secret[_-]?key|secret)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._~+/=-]{8,}'; then
      report "Secret" "$commit" "$path" "$line_no" "Secret-like assignment found"
    fi

    if printf '%s\n' "$line" | grep -Eq -- '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'; then
      report "Private key" "$commit" "$path" "$line_no" "Private key material found"
    fi

    if printf '%s\n' "$line" | grep -Eq 'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}'; then
      report "JWT token" "$commit" "$path" "$line_no" "JWT-like value found"
    fi

    emails="$(printf '%s\n' "$line" | grep -Eio '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' || true)"
    if [ -n "$emails" ]; then
      while IFS= read -r email; do
        [ -n "$email" ] || continue
        if [ -n "$ALLOW_EMAIL_REGEX" ] && printf '%s\n' "$email" | grep -Eiq "$ALLOW_EMAIL_REGEX"; then
          continue
        fi
        report "Email address" "$commit" "$path" "$line_no" "Email address found: ${email}"
      done <<EOEMAIL
$emails
EOEMAIL
    fi
  done <"$tmp"

  rm -f "$tmp"
}

while IFS=$'\t' read -r commit path; do
  [ -n "${commit:-}" ] || continue
  [ -n "${path:-}" ] || continue
  scan_blob "$commit" "$path"
done

if [ "$FAILED" -ne 0 ]; then
  echo "remote: =================================================="
  echo "remote: SECURITY SCAN FAILED - PUSH REJECTED"
  echo "remote: Remove the sensitive value and push again."
  echo "remote: =================================================="
  exit 1
fi

echo "remote: Security scan passed."
exit 0
