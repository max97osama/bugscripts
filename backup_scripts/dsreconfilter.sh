#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <urls.txt> [target_domain]"
    exit 1
fi

INPUT="$1"

if command -v dsurlfilter >/dev/null 2>&1; then
    dsurlfilter "$@"
else
    echo "[-] dsurlfilter not found on PATH; running inline fallback."
    dsurlfilter "$INPUT" 2>/dev/null || true
fi

ALLJS="alljs.txt"
FINDINGS="Findings.txt"
JSECRETS="jsecrets.txt"

> "$ALLJS"
> "$FINDINGS"
> "$JSECRETS"

PATTERN='(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|secret|password|passwd|pwd|access[_-]?key|access[_-]?token|auth[_-]?token|authorization|bearer|client[_-]?secret|private[_-]?key|aws_access_key_id|aws_secret_access_key|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|firebase|mongodb\+srv|x-api-key)'

STRICT_PATTERN='(AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|mongodb\+srv://[^[:space:]"'"'"']+|(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|secret|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|x-api-key)[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9_.\/+=-]{10,}["'"'"'])'

FALSE_POSITIVE='(your[_-]?(api)?[_-]?key|xxxxxxxx|00000000|changeme|example\.com|placeholder|dummy|test[_-]?key|\{\{|\$\{|<[a-zA-Z])'

if [ ! -f js.txt ]; then
    grep -iE "\.js(\?.*)?$" "$INPUT" > js.txt
fi

if [ ! -s js.txt ]; then
    echo "[-] No JS files found in $INPUT, nothing to scan."
    exit 0
fi

while IFS= read -r url; do
    [ -z "$url" ] && continue

    CONTENT=$(timeout 20 curl -s --max-time 15 "$url")
    echo "$CONTENT" >> "$ALLJS"

    echo "$CONTENT" | grep -inE "$PATTERN" | while IFS= read -r line; do
        echo "URL: $url" >> "$FINDINGS"
        echo "$line" >> "$FINDINGS"
        echo "" >> "$FINDINGS"
    done

    echo "$CONTENT" | grep -inE "$STRICT_PATTERN" | grep -viE "$FALSE_POSITIVE" | while IFS= read -r line; do
        echo "URL: $url" >> "$JSECRETS"
        echo "$line" >> "$JSECRETS"
        echo "" >> "$JSECRETS"
    done
done < js.txt

sort -u "$ALLJS" -o "$ALLJS"

echo "[+] alljs.txt: $(wc -l < "$ALLJS")"
echo "[+] Findings.txt entries: $(grep -c '^URL:' "$FINDINGS")"
echo "[+] jsecrets.txt entries: $(grep -c '^URL:' "$JSECRETS")"
