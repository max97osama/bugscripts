#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <subdomains.txt|domain>"
    echo "  Detects subdomain takeover candidates via subjack + nuclei + CNAME analysis."
    exit 1
fi

INPUT="$1"
OUT="takeover.txt"
> "$OUT"

TMP="/tmp/takeover_$$"
mkdir -p "$TMP"

TARGETS="$TMP/targets.txt"
> "$TARGETS"

if [ -f "$INPUT" ]; then
    grep -vE '^\s*$' "$INPUT" | sort -u > "$TARGETS"
else
    echo "$INPUT" > "$TARGETS"
fi

echo "[*] Running subjack on $(wc -l < "$TARGETS") targets..."
if command -v subjack >/dev/null 2>&1; then
    subjack -w "$TARGETS" -t 3 -timeout 20 -o "$OUT" -ssl -c /root/go/src/github.com/haccer/subjack/fingerprints.json 2>/dev/null \
        || subjack -w "$TARGETS" -t 3 -timeout 20 -o "$OUT" -ssl 2>/dev/null
else
    echo "[-] subjack not found, skipping subjack pass."
fi

echo "[*] Running nuclei takeover templates..."
if command -v nuclei >/dev/null 2>&1; then
    nuclei -list "$TARGETS" \
        -t ~/nuclei-templates/http/takeovers/ \
        -c 5 \
        -rl 20 \
        -timeout 20 \
        -silent \
        -o "$TMP/nuclei_tko.txt" 2>/dev/null
    cat "$TMP/nuclei_tko.txt" >> "$OUT" 2>/dev/null
else
    echo "[-] nuclei not found, skipping nuclei pass."
fi

echo "[*] Analysing CNAME targets (dangling records)..."
while IFS= read -r target; do
    target=$(echo "$target" | tr -d '[:space:]')
    [ -z "$target" ] && continue
    CNAME=$(dig +short CNAME "$target" 2>/dev/null | head -1)
    if echo "$CNAME" | grep -qiE "(github|github\.io|herokuapp|aws\.[a-z-]+\.com|s3[-.]|cname\.[a-z-]+\.io|azurewebsites|cloudfront|pantheon|netlify|vercel|surge\.sh|readme\.io|ghost\.io|mashery|status\.io|zendesk|accessibility|tictail|wordpress\.com)"; then
        echo "[CANDIDATE] $target -> $CNAME" >> "$OUT"
        echo "[CANDIDATE] $target -> $CNAME"
    fi
    sleep 2
done < "$TARGETS"

sort -u "$OUT" -o "$OUT"
echo "[+] Done. Takeover candidates in $OUT: $(wc -l < "$OUT") lines."

rm -rf "$TMP"
