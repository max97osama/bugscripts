#!/bin/bash

INPUT="${1:-urls.txt}"
OUTPUT="xssreport.txt"

> "$OUTPUT"

while IFS= read -r url; do
    [ -z "$url" ] && continue

    DALFOX_OUT=$(dalfox url "$url" --silence --no-color --skip-bav 2>/dev/null)
    echo "$DALFOX_OUT" | grep -E "^\[POC\]" | while IFS= read -r line; do
        echo "[Dalfox] $url" >> "$OUTPUT"
        echo "$line" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    done

    XSS_OUT=$(xsstrike -u "$url" --skip-dom --console-log-level 0 2>/dev/null)
    if echo "$XSS_OUT" | grep -qi "Vulnerable webpage"; then
        echo "[XSStrike] $url" >> "$OUTPUT"
        echo "$XSS_OUT" | grep -iE "Payload|Vulnerable webpage|Efficiency|Confidence" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    fi
done < "$INPUT"