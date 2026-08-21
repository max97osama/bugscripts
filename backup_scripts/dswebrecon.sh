#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <subdomains.txt|domain>"
    echo "  WAF detection, security-header audit, tech fingerprint, TLS info."
    exit 1
fi

INPUT="$1"
OUT="webrecon.txt"
WAF_OUT="waf.txt"
HDR_OUT="headers.txt"
TECH_OUT="techsummary.txt"

> "$OUT"
> "$WAF_OUT"
> "$HDR_OUT"
> "$TECH_OUT"

TMP="/tmp/webrecon_$$"
mkdir -p "$TMP"

TARGETS="$TMP/targets.txt"
> "$TARGETS"

if [ -f "$INPUT" ]; then
    grep -vE '^\s*$' "$INPUT" | sort -u > "$TARGETS"
else
    echo "$INPUT" > "$TARGETS"
fi

echo "======================================================================" >> "$OUT"
echo "WEB RECON REPORT - $(date)" >> "$OUT"
echo "======================================================================" >> "$OUT"

while IFS= read -r target; do
    target=$(echo "$target" | tr -d '[:space:]')
    [ -z "$target" ] && continue

    URL="https://$target"
    echo "" >> "$OUT"
    echo "### $target ###" >> "$OUT"

    echo "--- Request headers ---" >> "$OUT"
    HDR=$(curl -skI --max-time 12 -A "Mozilla/5.0" "$URL")
    echo "$HDR" >> "$OUT"
    echo "$HDR" >> "$HDR_OUT"
    echo "--- $target ---" >> "$HDR_OUT"

    echo "--- WAF detection ---" >> "$OUT"
    WAF=$(wafw00f "$URL" 2>/dev/null | grep -iE "is behind|no waf|not behind" || echo "unknown")
    echo "$WAF" >> "$OUT"
    echo "$target : $WAF" >> "$WAF_OUT"

    echo "--- Security header audit ---" >> "$OUT"
    for h in "strict-transport-security" "content-security-policy" "x-frame-options" "x-content-type-options" "referrer-policy" "permissions-policy" "access-control-allow-origin"; do
        if echo "$HDR" | grep -qi "^$h:"; then
            echo "  [OK]   $h: $(echo "$HDR" | grep -i "^$h:" | tr -d '\r')" >> "$OUT"
        else
            echo "  [MISS] $h" >> "$OUT"
        fi
    done

    echo "--- Cookie flags ---" >> "$OUT"
    echo "$HDR" | grep -i "^set-cookie:" | tr -d '\r' | while read -r c; do
        if echo "$c" | grep -qi "httponly"; then
            echo "  [OK]   HttpOnly on $(echo "$c" | awk '{print $2}' | cut -d= -f1)" >> "$OUT"
        else
            echo "  [MISS] HttpOnly on $(echo "$c" | awk '{print $2}' | cut -d= -f1)" >> "$OUT"
        fi
        if echo "$c" | grep -qi "secure"; then
            echo "  [OK]   Secure on $(echo "$c" | awk '{print $2}' | cut -d= -f1)" >> "$OUT"
        else
            echo "  [MISS] Secure on $(echo "$c" | awk '{print $2}' | cut -d= -f1)" >> "$OUT"
        fi
    done

    echo "--- Tech fingerprint (httpx) ---" >> "$OUT"
    echo "$URL" | httpx -tech-detect -status-code -title -server -silent 2>/dev/null >> "$OUT"
    echo "$URL" | httpx -tech-detect -silent 2>/dev/null >> "$TECH_OUT"

    echo "--- TLS / JARM ---" >> "$OUT"
    tlsx -host "$target" -port 443 -silent -jarm 2>/dev/null >> "$OUT"

    echo "" >> "$OUT"
    sleep 2
done < "$TARGETS"

echo "--- Tech summary (dedup) ---" >> "$TECH_OUT"
sort -u "$TECH_OUT" -o "$TECH_OUT"

echo "[+] Done."
echo "[+] webrecon.txt (full): $(wc -l < "$OUT") lines"
echo "[+] waf.txt: $(wc -l < "$WAF_OUT") hosts"
echo "[+] headers.txt: $(wc -l < "$HDR_OUT") lines"
echo "[+] techsummary.txt: $(wc -l < "$TECH_OUT") lines"

rm -rf "$TMP"
