#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <domain|domains.txt> <depth> <wordlist.txt>"
    exit 1
fi

INPUT="$1"
DEPTH="$2"
WORDLIST="$3"

CRAWL_OUT="curls.txt"
URLS_FILE="urls.txt"

touch "$CRAWL_OUT" "$URLS_FILE"

TARGETS="/tmp/crawl_targets_$$.txt"
> "$TARGETS"

if [ -f "$INPUT" ]; then
    while IFS= read -r line; do
        line=$(echo "$line" | tr -d '[:space:]')
        [ -z "$line" ] && continue
        if echo "$line" | grep -qE "^https?://"; then
            echo "$line" >> "$TARGETS"
        else
            echo "https://$line" >> "$TARGETS"
        fi
    done < "$INPUT"
else
    if echo "$INPUT" | grep -qE "^https?://"; then
        echo "$INPUT" >> "$TARGETS"
    else
        echo "https://$INPUT" >> "$TARGETS"
    fi
fi

sort -u "$TARGETS" -o "$TARGETS"

echo "[*] Total targets: $(wc -l < "$TARGETS")"

RAW_ALL="/tmp/crawl_raw_$$.txt"
> "$RAW_ALL"

while IFS= read -r TARGET; do
    echo "[*] Crawling: $TARGET"

    echo "[*] Running hakrawler on $TARGET..."
    echo "$TARGET" | hakrawler \
        -depth "$DEPTH" \
        -subs \
        -u \
        2>/dev/null >> "$RAW_ALL"

    sleep 5

    echo "[*] Running katana on $TARGET..."
    katana -u "$TARGET" \
        -d "$DEPTH" \
        -jc \
        -w 1 \
        -rl 5 \
        -timeout 10 \
        -silent \
        -wc "$WORDLIST" \
        2>/dev/null >> "$RAW_ALL"

    sleep 5

    echo "[*] Running gospider on $TARGET..."
    gospider -s "$TARGET" \
        -d "$DEPTH" \
        -t 1 \
        -c 1 \
        -w \
        -a \
        --no-redirect \
        -q \
        2>/dev/null | grep -oE "https?://[^ ]+" >> "$RAW_ALL"

    sleep 8

done < "$TARGETS"

echo "[*] Deduplicating and filtering results..."

grep -oE "https?://[^ ]+" "$RAW_ALL" | \
    sort -u > /tmp/crawl_deduped_$$.txt

cat /tmp/crawl_deduped_$$.txt >> "$CRAWL_OUT"
sort -u "$CRAWL_OUT" -o "$CRAWL_OUT"

cat /tmp/crawl_deduped_$$.txt >> "$URLS_FILE"
sort -u "$URLS_FILE" -o "$URLS_FILE"

echo "[+] Done."
echo "[+] curls.txt total links: $(wc -l < "$CRAWL_OUT")"
echo "[+] urls.txt total links: $(wc -l < "$URLS_FILE")"

rm -f "$TARGETS" "$RAW_ALL" /tmp/crawl_deduped_$$.txt
