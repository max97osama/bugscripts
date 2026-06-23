#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <domain> [-l subdomains.txt]"
    exit 1
fi

DOMAIN="$1"
SUBDOMAINS_FILE=""

if [ "$2" = "-l" ] && [ -n "$3" ]; then
    SUBDOMAINS_FILE="$3"
fi

URLS_OUT="urls.txt"
JS_OUT="js.txt"
PARAMS_OUT="parameters.txt"

> "$URLS_OUT"
> "$JS_OUT"
> "$PARAMS_OUT"

ALL_RAW="/tmp/all_raw_$$.txt"
TARGETS="/tmp/targets_$$.txt"

> "$ALL_RAW"
> "$TARGETS"

if [ -n "$SUBDOMAINS_FILE" ] && [ -f "$SUBDOMAINS_FILE" ]; then
    while IFS= read -r sub; do
        sub=$(echo "$sub" | tr -d '[:space:]')
        [ -z "$sub" ] && continue
        echo "$sub" >> "$TARGETS"
    done < "$SUBDOMAINS_FILE"
else
    echo "$DOMAIN" >> "$TARGETS"
fi

while IFS= read -r TARGET; do
    echo "[*] Gathering URLs for: $TARGET"

    gau "$TARGET" \
        --threads 1 \
        --timeout 10 \
        --retries 2 \
        2>/dev/null >> "$ALL_RAW"

    sleep 3

    waybackurls "$TARGET" 2>/dev/null >> "$ALL_RAW"

    sleep 3

    paramspider -d "$TARGET" \
        --quiet \
        2>/dev/null | grep -oE "https?://[^ ]+" >> "$ALL_RAW"

    sleep 5

done < "$TARGETS"

echo "[*] Deduplicating and validating URLs..."

sort -u "$ALL_RAW" > /tmp/deduped_$$.txt

httpx -l /tmp/deduped_$$.txt \
    -threads 1 \
    -rate-limit 5 \
    -timeout 10 \
    -silent \
    -mc 200,201,301,302,307,401,403 \
    2>/dev/null > /tmp/httpx_live_$$.txt

grep -oE "https?://[^ ]+" /tmp/httpx_live_$$.txt | sort -u > /tmp/live_clean_$$.txt

grep -iE "\.js(\?.*)?$" /tmp/live_clean_$$.txt > "$JS_OUT"

grep -ivE "\.(jpg|jpeg|png|gif|svg|ico|bmp|webp|css|json|js|woff|woff2|ttf|eot|pdf|mp4|mp3|zip|tar|gz)(\?.*)?$" \
    /tmp/live_clean_$$.txt > "$URLS_OUT"

grep -E "\?[^=]+=|&[^=]+=" "$URLS_OUT" > "$PARAMS_OUT"

echo "[+] Done."
echo "[+] urls.txt: $(wc -l < "$URLS_OUT") URLs"
echo "[+] js.txt: $(wc -l < "$JS_OUT") JS files"
echo "[+] parameters.txt: $(wc -l < "$PARAMS_OUT") URLs with parameters"

rm -f "$ALL_RAW" "$TARGETS" /tmp/deduped_$$.txt \
    /tmp/httpx_live_$$.txt /tmp/live_clean_$$.txt