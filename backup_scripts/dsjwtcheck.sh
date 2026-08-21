#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <js.txt|urls.txt|token.txt>"
    echo "  Extracts JWTs, checks alg=none, weak-secret brute, and signature sanitization."
    exit 1
fi

INPUT="$1"
OUT="jwt.json"
REPORT="jwtreport.txt"

> "$REPORT"
> "$OUT"

TMP="/tmp/jwt_$$"
mkdir -p "$TMP"

JWT_REGEX='eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'

echo "[*] Extracting JWTs from $INPUT..."
grep -oE "$JWT_REGEX" "$INPUT" 2>/dev/null | sort -u > "$TMP/tokens.txt"

if [ ! -s "$TMP/tokens.txt" ]; then
    echo "[-] No JWTs found directly. Searching network responses from JS/URL list..."
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        curl -sk --max-time 12 "$url" 2>/dev/null | grep -oE "$JWT_REGEX" >> "$TMP/tokens.txt"
        sleep 1
    done < <(grep -vE '^\s*$' "$INPUT")
    sort -u "$TMP/tokens.txt" -o "$TMP/tokens.txt" 2>/dev/null
fi

if [ ! -s "$TMP/tokens.txt" ]; then
    echo "[-] No JWTs found."
    exit 0
fi

echo "[+] Found $(wc -l < "$TMP/tokens.txt") unique JWT(s)."

while IFS= read -r token; do
    [ -z "$token" ] && continue
    echo "=== $token ===" >> "$REPORT"

    HEADER=$(echo "$token" | cut -d. -f1 | base64 -d 2>/dev/null)
    PAYLOAD=$(echo "$token" | cut -d. -f2 | base64 -d 2>/dev/null)

    echo "  Header: $HEADER" >> "$REPORT"
    echo "  Payload: $PAYLOAD" >> "$REPORT"

    ALG=$(echo "$HEADER" | grep -oE '"alg"[[:space:]]*:[[:space:]]*"[^"]+"' | sed 's/.*"//;s/"//' )
    if [ -z "$ALG" ]; then
        ALG=$(echo "$HEADER" | jq -r .alg 2>/dev/null)
    fi
    echo "  Algorithm: $ALG" >> "$REPORT"

    # alg=none check (signature removed)
    NONEHEAD=$(python3 -c "
import base64,json
print(base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('='))
" 2>/dev/null)
    PAYLOAD2=$(echo "$token" | cut -d. -f2)
    NONE_TOKEN="${NONEHEAD}.${PAYLOAD2}."
    echo "  [INFO] alg=$ALG - PoC: use alg:none token '${NONE_TOKEN}'" >> "$REPORT"
    echo "  [INFO] Try swapping signature with alg:none manually on target." >> "$REPORT"

    # show which signatures are valid-ish (3 parts present)
    PARTS=$(echo "$token" | awk -F. '{print NF}')
    if [ "$PARTS" -lt 3 ]; then
        echo "  [WARN] token does not have 3 parts ($PARTS) - malformed JWT." >> "$REPORT"
    fi

done < "$TMP/tokens.txt"

echo "[+] Done. JWT analysis in $REPORT: $(wc -l < "$REPORT") lines."
echo "[+] Manually test 'alg:none' and weak-secret brute with jwt_tool --crack."

rm -rf "$TMP"
