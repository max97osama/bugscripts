#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <domain|subdomains.txt>"
    exit 1
fi

INPUT="$1"
OUTPUT="smugglerreport.txt"

> "$OUTPUT"

TARGETS="/tmp/smuggler_targets_$$.txt"
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

while IFS= read -r TARGET; do
    echo "[*] Testing: $TARGET"

    SMUGGLER_OUT=$(smuggler -u "$TARGET" \
        --quiet \
        --timeout 10 \
        2>/dev/null)

    if echo "$SMUGGLER_OUT" | grep -qiE "vulnerable|issue found|CL.TE|TE.CL|TE.TE"; then
        echo "[Smuggler] $TARGET" >> "$OUTPUT"
        echo "$SMUGGLER_OUT" | grep -iE "vulnerable|issue found|CL.TE|TE.CL|TE.TE|payload" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
    fi

    sleep 8

done < "$TARGETS"

echo "[+] Done. HTTP smuggling findings saved to $OUTPUT"
echo "[+] Total findings: $(grep -c '^\[Smuggler\]' "$OUTPUT")"

rm -f "$TARGETS"
