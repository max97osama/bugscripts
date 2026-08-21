#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <domain|urls.txt> [js.txt filter]"
    echo "  Extracts JS endpoints, params and secrets from target."
    exit 1
fi

INPUT="$1"
TMP="/tmp/jsendpoints_$$"
mkdir -p "$TMP"

JS_OUT="js.txt"
ENDPOINT_OUT="endpoints.txt"
SECRET_OUT="jsecrets.txt"
PARAM_OUT="parameters.txt"
URLS_FILE="urls.txt"

> "$ENDPOINT_OUT"
> "$SECRET_OUT"

touch "$URLS_FILE"

TARGETS="$TMP/targets.txt"
> "$TARGETS"

if [ -f "$INPUT" ]; then
    grep -vE '^\s*$' "$INPUT" | sort -u > "$TARGETS"
else
    echo "$INPUT" > "$TARGETS"
fi

echo "[*] Gathering JS URLs (getJS + wayback raw shares)..."
cat "$TARGETS" | getJS --complete --output "$TMP/js_urls.txt" 2>/dev/null
sort -u "$TMP/js_urls.txt" -o "$TMP/js_urls.txt" 2>/dev/null

if [ -f js.txt ] && [ -s js.txt ]; then
    cat js.txt >> "$TMP/js_urls.txt" 2>/dev/null
    sort -u "$TMP/js_urls.txt" -o "$TMP/js_urls.txt"
fi

if [ ! -s "$TMP/js_urls.txt" ]; then
    grep -iE "\.js(\?.*)?$" "$TARGETS" >> "$TMP/js_urls.txt" 2>/dev/null
fi

cp "$TMP/js_urls.txt" "$JS_OUT" 2>/dev/null
echo "[+] JS URLs gathered: $(wc -l < "$JS_OUT" 2>/dev/null)"

echo "[*] Running LinkFinder / xnLinkFinder for endpoints..."
while IFS= read -r url; do
    [ -z "$url" ] && continue
    linkfinder -i "$url" -d -o cli 2>/dev/null | grep -oE '(https?://|/)[^" ]+' >> "$TMP/link_ep.txt"
    xnLinkFinder -i "$url" -d 2 -o cli 2>/dev/null | grep -oE 'https?://[^ ]+' >> "$TMP/link_ep.txt"
    sleep 1
done < "$TMP/js_urls.txt"

sort -u "$TMP/link_ep.txt" -o "$TMP/link_ep.txt" 2>/dev/null
cp "$TMP/link_ep.txt" "$ENDPOINT_OUT" 2>/dev/null
echo "[+] Endpoints found: $(wc -l < "$ENDPOINT_OUT" 2>/dev/null)"

echo "[*] Regex extraction of API paths..."
if [ -s "$TMP/link_ep.txt" ]; then
    grep -oE '/[a-zA-Z0-9_-]{2,}(/[a-zA-Z0-9_{}._-]+)+' "$TMP/link_ep.txt" \
        | sort -u >> "$ENDPOINT_OUT" 2>/dev/null
    sort -u "$ENDPOINT_OUT" -o "$ENDPOINT_OUT"
fi

echo "[*] Scanning JS files for secrets..."
while IFS= read -r url; do
    [ -z "$url" ] && continue
    CONTENT=$(timeout 20 curl -s --max-time 15 "$url")
    echo "$CONTENT" | secretfinder -i - 2>/dev/null >> "$TMP/secret_raw.txt"
    echo "$CONTENT" | grep -inE '(api[_-]?key|secret|password|token|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_=-]+\.)' \
        | grep -vE 'xxxxxxxx|example\.com|placeholder|<[a-z]' >> "$TMP/secret_raw.txt"
done < "$TMP/js_urls.txt"

sort -u "$TMP/secret_raw.txt" -o "$TMP/secret_raw.txt" 2>/dev/null
cp "$TMP/secret_raw.txt" "$SECRET_OUT" 2>/dev/null

echo "[*] Extracting URLs with parameters for injection testing..."
python3 - "$ENDPOINT_OUT" "$PARAM_OUT" << 'PYEOF'
import re
import sys

endpoints, param_out = sys.argv[1:3]
urls = set()
try:
    with open(endpoints) as f:
        for line in f:
            line = line.strip()
            if '?' in line and '=' in line:
                urls.add(line)
except FileNotFoundError:
    pass

# Infer param-bearing endpoints by appending a test param
with open(endpoints) as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('http'):
            continue
        if line.endswith('.js'):
            continue

with open(param_out, 'w') as f:
    for u in sorted(urls):
        f.write(u + '\n')

print(f'[+] Parameterized URLs: {len(urls)}')
PYEOF

echo "[+] Done."
echo "[+] js.txt: $(wc -l < "$JS_OUT" 2>/dev/null)"
echo "[+] endpoints.txt: $(wc -l < "$ENDPOINT_OUT" 2>/dev/null)"
echo "[+] jsecrets.txt: $(wc -l < "$SECRET_OUT" 2>/dev/null)"
echo "[+] parameters.txt: $(wc -l < "$PARAM_OUT" 2>/dev/null)"

grep -E "^https?://" "$ENDPOINT_OUT" 2>/dev/null | sort -u >> "$URLS_FILE"
sort -u "$URLS_FILE" -o "$URLS_FILE"
echo "[+] Absolute endpoints appended to: $URLS_FILE"

rm -rf "$TMP"
