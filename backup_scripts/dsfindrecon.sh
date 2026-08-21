#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <domain|domains.txt>"
    exit 1
fi

INPUT="$1"

FIND_OUT="findurls.txt"
URLS_FILE="urls.txt"

touch "$FIND_OUT" "$URLS_FILE"

TARGETS="/tmp/js_targets_$$.txt"
RAW_ALL="/tmp/js_raw_$$.txt"

> "$TARGETS"
> "$RAW_ALL"

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

while IFS= read -r TARGET; do
    DOMAIN=$(echo "$TARGET" | sed 's|https\?://||' | sed 's|/.*||')
    echo "[*] Processing: $TARGET"

    echo "[*] Running assetfinder on $DOMAIN..."
    assetfinder --subs-only "$DOMAIN" \
        2>/dev/null | sed "s/^/https:\/\//" >> "$RAW_ALL"

    sleep 5

    echo "[*] Running xnLinkFinder on $TARGET..."
    xnLinkFinder \
        -i "$TARGET" \
        -d "$DOMAIN" \
        -o cli \
        2>/dev/null | grep -oE "https?://[^ ]+" >> "$RAW_ALL"

    sleep 5

    echo "[*] Running urlfinder on $TARGET..."
    urlfinder -d "$DOMAIN" \
        -all \
        -silent \
        2>/dev/null | grep -oE "https?://[^ ]+" >> "$RAW_ALL"

    sleep 8

done < "$TARGETS"

echo "[*] Deduplicating results..."

grep -oE "https?://[^ ]+" "$RAW_ALL" | \
    sort -u > /tmp/js_deduped_$$.txt

cat /tmp/js_deduped_$$.txt >> "$FIND_OUT"
sort -u "$FIND_OUT" -o "$FIND_OUT"

cat /tmp/js_deduped_$$.txt >> "$URLS_FILE"
sort -u "$URLS_FILE" -o "$URLS_FILE"

echo "[+] Done."
echo "[+] findurls.txt total links: $(wc -l < "$FIND_OUT")"
echo "[+] urls.txt total links: $(wc -l < "$URLS_FILE")"

rm -f "$TARGETS" "$RAW_ALL" /tmp/js_deduped_$$.txt
