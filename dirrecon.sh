#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <domain> <subdomains.txt> <wordlist.txt>"
    exit 1
fi

DOMAIN="$1"
SUBDOMAINS_FILE="$2"
WORDLIST="$3"
OUTPUT="burl.txt"

> "$OUTPUT"

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

while IFS= read -r TARGET; do
    echo "[*] Scanning: $TARGET"

    echo "[*] Running ffuf on $TARGET..."
    ffuf -u "$TARGET/FUZZ" \
        -w "$WORDLIST" \
        -t 1 \
        -rate 3 \
        -timeout 15 \
        -mc 200,201,204,301,302,307,401,403 \
        -o /tmp/ffuf_temp_$$.json \
        -of json \
        -s 2>/dev/null

    if [ -f /tmp/ffuf_temp_$$.json ]; then
        python3 -c "
import json
with open('/tmp/ffuf_temp_$$.json') as f:
    data = json.load(f)
for r in data.get('results', []):
    url = r.get('url', '')
    status = r.get('status', '')
    if url:
        print(f'{url} [{status}]')
" >> "$OUTPUT" 2>/dev/null
        rm -f /tmp/ffuf_temp_$$.json
    fi

    sleep 10

    echo "[*] Running dirsearch on $TARGET..."
    dirsearch -u "$TARGET" \
        -w "$WORDLIST" \
        -t 1 \
        --delay=2 \
        --timeout=15 \
        -e php,html,js,txt,json,xml,bak,old,zip \
        --plain-text-report=/tmp/dirsearch_temp_$$.txt \
        -q 2>/dev/null

    if [ -f /tmp/dirsearch_temp_$$.txt ]; then
        grep -E "^\[" /tmp/dirsearch_temp_$$.txt | while read -r line; do
            echo "$TARGET $line" >> "$OUTPUT"
        done
        rm -f /tmp/dirsearch_temp_$$.txt
    fi

    sleep 10

    echo "[*] Running gobuster on $TARGET..."
    gobuster dir \
        -u "$TARGET" \
        -w "$WORDLIST" \
        -t 1 \
        --delay 2000ms \
        --timeout 15s \
        -q \
        -o /tmp/gobuster_temp_$$.txt 2>/dev/null

    if [ -f /tmp/gobuster_temp_$$.txt ]; then
        while IFS= read -r line; do
            echo "$TARGET $line" >> "$OUTPUT"
        done < /tmp/gobuster_temp_$$.txt
        rm -f /tmp/gobuster_temp_$$.txt
    fi

    sleep 15

done < "$TARGETS"

sort -u "$OUTPUT" -o "$OUTPUT"

echo "[+] Scan complete."
echo "[+] Total found URLs: $(wc -l < "$OUTPUT")"
echo "[+] Results saved to: $OUTPUT"

rm -f "$TARGETS"