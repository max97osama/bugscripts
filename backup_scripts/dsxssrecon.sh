#!/bin/bash

INPUT="${1:-parameters.txt}"
PAYLOADS_FILE="${2:-}"
OUTPUT="xssreport.txt"

> "$OUTPUT"

USE_PAYLOADS=0
FIRST_PAYLOAD=""

if [ -n "$PAYLOADS_FILE" ] && [ -f "$PAYLOADS_FILE" ] && [ -s "$PAYLOADS_FILE" ]; then
    echo "[*] Using custom payload list: $PAYLOADS_FILE"
    USE_PAYLOADS=1
    FIRST_PAYLOAD=$(head -n 1 "$PAYLOADS_FILE")
else
    echo "[*] No payload list provided, using tool defaults."
fi

while IFS= read -r url; do
    [ -z "$url" ] && continue

    if [ "$USE_PAYLOADS" -eq 1 ]; then
        DALFOX_OUT=$(dalfox url "$url" --silence --no-color --skip-bav --custom-payload "$PAYLOADS_FILE" --only-custom-payload 2>/dev/null)
    else
        DALFOX_OUT=$(dalfox url "$url" --silence --no-color --skip-bav 2>/dev/null)
    fi
    echo "$DALFOX_OUT" | grep -E "^\[POC\]" | while IFS= read -r line; do
        echo "[Dalfox] $url" >> "$OUTPUT"
        echo "$line" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    done

    if [ "$USE_PAYLOADS" -eq 1 ]; then
        XSS_OUT=$(xsstrike -u "$url" --skip-dom --console-log-level 0 --payload-list "$PAYLOADS_FILE" 2>/dev/null)
    else
        XSS_OUT=$(xsstrike -u "$url" --skip-dom --console-log-level 0 2>/dev/null)
    fi
    if echo "$XSS_OUT" | grep -qi "Vulnerable webpage"; then
        echo "[XSStrike] $url" >> "$OUTPUT"
        echo "$XSS_OUT" | grep -iE "Payload|Vulnerable webpage|Efficiency|Confidence" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    fi

    LOXS_OUT=$(loxs -u "$url" 2>/dev/null)
    if echo "$LOXS_OUT" | grep -qi "vulnerable"; then
        echo "[Loxs] $url" >> "$OUTPUT"
        echo "$LOXS_OUT" | grep -iE "vulnerable|payload" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    fi

    if [ "$USE_PAYLOADS" -eq 1 ]; then
        PWNXSS_OUT=$(pwnxss -u "$url" --single --payload "$FIRST_PAYLOAD" 2>/dev/null)
    else
        PWNXSS_OUT=$(pwnxss -u "$url" --single 2>/dev/null)
    fi
    if echo "$PWNXSS_OUT" | grep -qi "vulnerable"; then
        echo "[PwnXSS] $url" >> "$OUTPUT"
        echo "$PWNXSS_OUT" | grep -iE "vulnerable|payload|xss found" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    fi

    if [ "$USE_PAYLOADS" -eq 1 ]; then
        SPEARX_OUT=$(xspear -u "$url" -a --custom-payload "$PAYLOADS_FILE" -v 0 2>/dev/null)
    else
        SPEARX_OUT=$(xspear -u "$url" -a -v 0 2>/dev/null)
    fi
    if echo "$SPEARX_OUT" | grep -qi "vulnerable"; then
        echo "[XSpear] $url" >> "$OUTPUT"
        echo "$SPEARX_OUT" | grep -iE "vulnerable|payload" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    fi

    if [ "$USE_PAYLOADS" -eq 1 ]; then
        XSSFINDER_OUT=$(xssfinder -u "$url" -p "$FIRST_PAYLOAD" 2>/dev/null)
    else
        XSSFINDER_OUT=$(xssfinder -u "$url" 2>/dev/null)
    fi
    if echo "$XSSFINDER_OUT" | grep -qi "vulnerable"; then
        echo "[XSSFinder] $url" >> "$OUTPUT"
        echo "$XSSFINDER_OUT" | grep -iE "vulnerable|payload" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    fi

    XSSAUTO_OUT=$(xss-automation -u "$url" 2>/dev/null)
    if echo "$XSSAUTO_OUT" | grep -qi "vulnerable"; then
        echo "[XSS-Automation] $url" >> "$OUTPUT"
        echo "$XSSAUTO_OUT" | grep -iE "vulnerable|payload" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    fi

    sleep 2

done < "$INPUT"

echo "[+] Done. XSS findings saved to $OUTPUT"
