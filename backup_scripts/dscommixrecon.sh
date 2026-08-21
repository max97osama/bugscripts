#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <parameters.txt>"
    exit 1
fi

INPUT="$1"
OUTPUT="cmdireport.txt"

> "$OUTPUT"

if [ ! -s "$INPUT" ]; then
    echo "[-] $INPUT is empty or missing, nothing to scan."
    exit 0
fi

echo "[*] Total URLs to test: $(wc -l < "$INPUT")"

while IFS= read -r url; do
    [ -z "$url" ] && continue
    echo "[*] Testing: $url"

    COMMIX_OUT=$(commix -u "$url" \
        --batch \
        --level=1 \
        --time-sec=5 \
        --skip-waf \
        --no-logging \
        2>/dev/null)

    if echo "$COMMIX_OUT" | grep -qiE "is vulnerable|injectable|target url is vulnerable"; then
        echo "[Commix] $url" >> "$OUTPUT"
        echo "$COMMIX_OUT" | grep -iE "is vulnerable|injectable|technique|payload|parameter" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    fi

    sleep 5

done < "$INPUT"

echo "[+] Done. Command injection findings saved to $OUTPUT"
echo "[+] Total findings: $(grep -c '^\[Commix\]' "$OUTPUT")"
