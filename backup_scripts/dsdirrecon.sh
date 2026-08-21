#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <domain> <subdomains.txt> <wordlist.txt>"
    exit 1
fi

DOMAIN="$1"
SUBDOMAINS_FILE="$2"
WORDLIST="$3"
OUTPUT="burl.txt"
URLS_FILE="urls.txt"

> "$OUTPUT"

touch "$URLS_FILE"

TARGETS="/tmp/targets_$$.txt"
> "$TARGETS"

echo "https://$DOMAIN" >> "$TARGETS"

while IFS= read -r sub; do
    sub=$(echo "$sub" | tr -d '[:space:]')
    [ -z "$sub" ] && continue
    if echo "$sub" | grep -q "^http"; then
        echo "$sub" >> "$TARGETS"
    else
        echo "https://$sub" >> "$TARGETS"
    fi
done < "$SUBDOMAINS_FILE"

sort -u "$TARGETS" -o "$TARGETS"

echo "[*] Total targets: $(wc -l < "$TARGETS")"

if command -v ffuf >/dev/null 2>&1; then
    echo "[*] Using ffuf as primary directory fuzzer."
    while IFS= read -r TARGET; do
        echo "[*] ffuf scanning: $TARGET"
        ffuf -u "$TARGET/FUZZ" \
            -w "$WORDLIST" \
            -t 2 \
            -rate 5 \
            -timeout 10 \
            -mc 200,201,204,301,302,307,401,403 \
            -recursion \
            -recursion-depth 2 \
            -o "/tmp/ffuf_dir_$$.json" \
            -of json \
            -s 2>/dev/null

        if [ -f /tmp/ffuf_dir_$$.json ]; then
            python3 - "$$" << 'PYEOF'
import json
import sys

pid = sys.argv[1]
try:
    with open(f'/tmp/ffuf_dir_{pid}.json') as f:
        data = json.load(f)
    with open('burl.txt', 'a') as out:
        for r in data.get('results', []):
            url = r.get('url', '')
            status = r.get('status', '')
            if url:
                out.write(f'{url} [{status}]\n')
except FileNotFoundError:
    pass
PYEOF
            rm -f /tmp/ffuf_dir_$$.json
        fi

        sleep 10
    done < "$TARGETS"
else
    echo "[-] ffuf not found; falling back to dirsearch and gobuster (slower)."
    while IFS= read -r TARGET; do
        echo "[*] dirsearch scanning: $TARGET"
        if command -v dirsearch >/dev/null 2>&1; then
            dirsearch -u "$TARGET" \
                -w "$WORDLIST" \
                -t 3 \
                --timeout=10 \
                -e php,html,js,txt,json,xml,bak,old,zip \
                --plain-text-report=/tmp/dirsearch_dir_$$.txt \
                -q 2>/dev/null
            if [ -f /tmp/dirsearch_dir_$$.txt ]; then
                grep -E "^\[" /tmp/dirsearch_dir_$$.txt | while read -r line; do
                    echo "$TARGET $line" >> "$OUTPUT"
                done
                rm -f /tmp/dirsearch_dir_$$.txt
            fi
        fi

        echo "[*] gobuster scanning: $TARGET"
        if command -v gobuster >/dev/null 2>&1; then
            gobuster dir \
                -u "$TARGET" \
                -w "$WORDLIST" \
                -t 3 \
                --delay 300ms \
                --timeout 10s \
                -q \
                -o /tmp/gobuster_dir_$$.txt 2>/dev/null
            if [ -f /tmp/gobuster_dir_$$.txt ]; then
                while IFS= read -r line; do
                    echo "$TARGET $line" >> "$OUTPUT"
                done < /tmp/gobuster_dir_$$.txt
                rm -f /tmp/gobuster_dir_$$.txt
            fi
        fi

        sleep 10
    done < "$TARGETS"
fi

sort -u "$OUTPUT" -o "$OUTPUT"

grep -oE "https?://[^ ]+" "$OUTPUT" | sed 's/ \[[0-9]*\]$//' | sort -u >> "$URLS_FILE"
sort -u "$URLS_FILE" -o "$URLS_FILE"

echo "[+] Scan complete."
echo "[+] Total found URLs: $(wc -l < "$OUTPUT")"
echo "[+] Results saved to: $OUTPUT"
echo "[+] URLs appended to: $URLS_FILE"

rm -f "$TARGETS"
