#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <domain|subdomains.txt> [prior_urls.txt]"
    echo "  Pulls wayback/archive URL history, dedupes against last run, live-checks."
    exit 1
fi

INPUT="$1"
PRIOR="${2:-}"

TMP="/tmp/paralytics_$$"
mkdir -p "$TMP"

OUT="new_urls.txt"
LIVE="live_urls.txt"
URLS_FILE="urls.txt"
> "$OUT"
> "$LIVE"

touch "$URLS_FILE"

TARGETS="$TMP/targets.txt"
> "$TARGETS"

if [ -f "$INPUT" ]; then
    grep -vE '^\s*$' "$INPUT" | sort -u > "$TARGETS"
else
    echo "$INPUT" > "$TARGETS"
fi

echo "[*] Collecting archive URLs (gau + waymore + waybackurls, sequential)..."
while IFS= read -r target; do
    target=$(echo "$target" | tr -d '[:space:]')
    [ -z "$target" ] && continue
    gau "$target" --threads 1 2>/dev/null >> "$TMP/raw.txt"
    sleep 3
    waybackurls "$target" 2>/dev/null >> "$TMP/raw.txt"
    sleep 3
    if command -v waymore >/dev/null 2>&1; then
        waymore -i "$target" -n -oU "$TMP/waymore_out" -mode U 2>/dev/null
        cat "$TMP/waymore_out/"* 2>/dev/null >> "$TMP/raw.txt"
        sleep 3
    fi
done < "$TARGETS"

sort -u "$TMP/raw.txt" -o "$TMP/raw.txt" 2>/dev/null
echo "[+] Archive URLs collected: $(wc -l < "$TMP/raw.txt" 2>/dev/null)"

echo "[*] Diffing against previous run..."
if [ -n "$PRIOR" ] && [ -f "$PRIOR" ]; then
    comm -23 <(sort -u "$TMP/raw.txt") <(sort -u "$PRIOR") > "$OUT"
else
    cp "$TMP/raw.txt" "$OUT"
fi

if [ "$#" -lt 2 ]; then
    echo "[*] Anew-based incremental (first run shows all)..."
    if command -v anew >/dev/null 2>&1 && [ -f urls.txt ]; then
        cat "$TMP/raw.txt" | anew urls.txt > "$OUT"
    else
        cp "$TMP/raw.txt" "$OUT"
    fi
fi

sort -u "$OUT" -o "$OUT" 2>/dev/null
echo "[+] New/unique URLs: $(wc -l < "$OUT" 2>/dev/null)"

echo "[*] Live-checking new URLs with httpx..."
if [ -s "$OUT" ]; then
    httpx -l "$OUT" \
        -threads 5 \
        -rate-limit 20 \
        -timeout 10 \
        -status-code \
        -mc 200,201,301,302,307,401,403 \
        -silent 2>/dev/null | grep -oE "https?://[^ ]+" | \
        sed 's/ \[[0-9]*\]$//' | sort -u > "$LIVE"
    echo "[+] Live URLs: $(wc -l < "$LIVE" 2>/dev/null)"
fi

echo "[+] Done."
echo "[+] new_urls.txt: $(wc -l < "$OUT" 2>/dev/null)"
echo "[+] live_urls.txt: $(wc -l < "$LIVE" 2>/dev/null)"

cat "$OUT" "$LIVE" 2>/dev/null >> "$URLS_FILE"
sort -u "$URLS_FILE" -o "$URLS_FILE"
echo "[+] new_urls.txt + live_urls.txt appended to: $URLS_FILE"

rm -rf "$TMP"
