#!/bin/bash

INPUT="${1:-js.txt}"

ALLJS="alljs.txt"
FINDINGS="Findings.txt"
SECRET_OUT="jsecrets.txt"
ENDPOINT_OUT="endpoints.txt"
PARAM_OUT="parameters.txt"
URLS_FILE="urls.txt"

> "$ALLJS"
> "$FINDINGS"
> "$SECRET_OUT"
> "$ENDPOINT_OUT"
> "$PARAM_OUT"

touch "$URLS_FILE"

TMP="/tmp/jsrecon_$$"
mkdir -p "$TMP"

PATTERN='(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|secret|password|passwd|pwd|access[_-]?key|access[_-]?token|auth[_-]?token|authorization|bearer|client[_-]?secret|private[_-]?key|aws_access_key_id|aws_secret_access_key|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|firebase|mongodb\+srv|x-api-key)'

JS_URLS="$TMP/js_urls.txt"
> "$JS_URLS"

if [ -f "$INPUT" ]; then
    cp "$INPUT" "$JS_URLS"
    sort -u "$JS_URLS" -o "$JS_URLS"
else
    # INPUT is a bare domain; getJS below will discover JS from it
    echo "$INPUT" > /dev/null
fi

echo "[*] Discovering JS files (getJS)..."
if command -v getJS >/dev/null 2>&1; then
    if [ -f "$INPUT" ]; then
        cat "$INPUT" | getJS --complete --output "$TMP/gotjs.txt" 2>/dev/null
        cat "$TMP/gotjs.txt" >> "$JS_URLS" 2>/dev/null
    else
        echo "$INPUT" | getJS --complete --output "$TMP/gotjs.txt" 2>/dev/null
        cat "$TMP/gotjs.txt" >> "$JS_URLS" 2>/dev/null
    fi
    sort -u "$JS_URLS" -o "$JS_URLS"
fi

if [ ! -s "$JS_URLS" ]; then
    echo "[-] No JS URLs provided or discovered. Nothing to scan."
    rm -rf "$TMP"
    exit 0
fi

cp "$JS_URLS" "js.txt" 2>/dev/null
echo "[+] JS URLs to process: $(wc -l < "$JS_URLS")"

while IFS= read -r url; do
    [ -z "$url" ] && continue

    CONTENT=$(timeout 20 curl -s --max-time 15 "$url")
    echo "$CONTENT" >> "$ALLJS"

    echo "$CONTENT" | grep -inE "$PATTERN" | while IFS= read -r line; do
        echo "URL: $url" >> "$FINDINGS"
        echo "$line" >> "$FINDINGS"
        echo "" >> "$FINDINGS"
    done

    echo "$CONTENT" | grep -inE "$PATTERN" | grep -vE 'xxxxxxxx|example\.com|placeholder|<[a-z]' \
        | while IFS= read -r line; do
            echo "URL: $url" >> "$SECRET_OUT"
            echo "$line" >> "$SECRET_OUT"
            echo "" >> "$SECRET_OUT"
        done

    echo "$CONTENT" | secretfinder -i - 2>/dev/null >> "$TMP/sf.txt" 2>/dev/null

    if command -v linkfinder >/dev/null 2>&1; then
        linkfinder -i "$url" -d -o cli 2>/dev/null | grep -oE '(https?://|/)[^" ]+' >> "$TMP/link_ep.txt"
    fi
    if command -v xnLinkFinder >/dev/null 2>&1; then
        xnLinkFinder -i "$url" -d 2 -o cli 2>/dev/null | grep -oE 'https?://[^ ]+' >> "$TMP/link_ep.txt"
    fi

    sleep 1
done < "$JS_URLS"

sort -u "$TMP/sf.txt" >> "$SECRET_OUT" 2>/dev/null
sort -u "$SECRET_OUT" -o "$SECRET_OUT"

sort -u "$TMP/link_ep.txt" >> "$ENDPOINT_OUT" 2>/dev/null
grep -oE '/[a-zA-Z0-9_-]{2,}(/[a-zA-Z0-9_{}._-]+)+' "$TMP/link_ep.txt" 2>/dev/null | sort -u >> "$ENDPOINT_OUT"
sort -u "$ENDPOINT_OUT" -o "$ENDPOINT_OUT"

grep -E "https?://[^ ]+\?[^=]+=" "$ENDPOINT_OUT" 2>/dev/null | sort -u > "$PARAM_OUT"

grep -E "^https?://" "$ENDPOINT_OUT" 2>/dev/null | sort -u >> "$URLS_FILE"
sort -u "$URLS_FILE" -o "$URLS_FILE"

sort -u "$ALLJS" -o "$ALLJS"

echo "[+] alljs.txt total lines: $(wc -l < "$ALLJS")"
echo "[+] Findings.txt entries: $(grep -c '^URL:' "$FINDINGS")"
echo "[+] jsecrets.txt entries: $(grep -c '^URL:' "$SECRET_OUT")"
echo "[+] endpoints.txt: $(wc -l < "$ENDPOINT_OUT") endpoints"
echo "[+] parameters.txt: $(wc -l < "$PARAM_OUT") param URLs"
echo "[+] js.txt: $(wc -l < "js.txt") JS URLs"

{
    echo ""
    echo "========================================================================="
    echo " [dsjsrecon] JS / ENDPOINTS / SECRETS $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================================================="
    echo "[*] JS files      : $(wc -l < js.txt 2>/dev/null | tr -d ' ')"
    echo "[*] endpoints.txt : $(wc -l < "$ENDPOINT_OUT" 2>/dev/null | tr -d ' ')"
    echo "[*] jsecrets.txt  : $(wc -l < "$SECRET_OUT" 2>/dev/null | tr -d ' ')"
    echo "--- jsecrets.txt ---"
    cat "$SECRET_OUT" 2>/dev/null
    echo ""
} >> fullreport.txt 2>/dev/null

rm -rf "$TMP"
