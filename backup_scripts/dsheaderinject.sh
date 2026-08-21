#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <urls.txt|domain>"
    echo "  Tests CRLF injection, Host-header attacks, and open redirect on live URLs."
    exit 1
fi

INPUT="$1"
OUT="headerinject.txt"
> "$OUT"

TMP="/tmp/headerinject_$$"
mkdir -p "$TMP"

TARGETS="$TMP/targets.txt"
> "$TARGETS"

if [ -f "$INPUT" ]; then
    grep -vE '^\s*$' "$INPUT" | sort -u > "$TARGETS"
else
    echo "https://$INPUT" > "$TARGETS"
fi

echo "======================================================================" >> "$OUT"
echo "HEADER INJECTION REPORT - $(date)" >> "$OUT"
echo "======================================================================" >> "$OUT"

echo "[*] CRLF injection via crlfuzz..."
if command -v crlfuzz >/dev/null 2>&1; then
    crlfuzz -l "$TARGETS" -s -t 5 2>/dev/null | tee -a "$TMP/crlf_$$.txt" >> "$OUT"
fi

echo "[*] Host-header injection test..."
CRLF_URLENCODE='%0d%0a'
while IFS= read -r target; do
    target=$(echo "$target" | tr -d '[:space:]')
    [ -z "$target" ] && continue

    echo "[*] $target" >> "$OUT"

    # PoC: inject a custom header via Host and Observe its reflection (cache poisoning / poisoning)
    RESP=$(curl -sk -o "$TMP/host_$$.txt" -w "%{http_code}" --max-time 10 \
        -H "Host: evil$target" "$target" 2>/dev/null)
    echo "    Host-injection attempt: Host: evil$target -> HTTP $RESP" >> "$OUT"
    rm -f "$TMP/host_$$.txt"

    # Reflected XSS / header injection via X-Forwarded-For reflection
    RESP=$(curl -sk -o "$TMP/xff_$$.txt" -w "%{http_code}" --max-time 10 \
        -H "X-Forwarded-For: techinsight.test" "$target" 2>/dev/null)
    if grep -qiE "techinsight\.test" "$TMP/xff_$$.txt" 2>/dev/null; then
        echo "    [REFLECTED] X-Forwarded-For header reflected in response ($target)" >> "$OUT"
        echo "    [REFLECTED] X-Forwarded-For reflected: $target"
    fi
    rm -f "$TMP/xff_$$.txt"
done < "$TARGETS"

echo "[*] Open-redirect check via gf redirect + manual header checks..."
if command -v gf >/dev/null 2>&1 && [ -f ~/.gf/redirect.json ]; then
    gf redirect "$TARGETS" 2>/dev/null > "$TMP/redirect_urls.txt"
    if [ -s "$TMP/redirect_urls.txt" ]; then
        grep -oE "https?://[^ ]+" "$TMP/redirect_urls.txt" | sort -u > "$TMP/redir.txt"
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            LOC=$(curl -sk -o /dev/null -D - --max-time 8 "$url" 2>/dev/null | grep -i "^location:" | tr -d '\r')
            if echo "$LOC" | grep -qEv "^\s*$" && echo "$LOC" | grep -qiE "$(echo "$url" | sed 's|https\?://||;s|/.*||')" | grep -vq .; then
                :
            fi
            if echo "$LOC" | grep -qiE "evil|//google|javascript:|data:"; then
                echo "[OPEN-REDIRECT?] $url -> $LOC" >> "$OUT"
                echo "[OPEN-REDIRECT?] $url"
            fi
        done < "$TMP/redir.txt"
    fi
fi

echo "[+] Done. Header injection findings in $OUT: $(wc -l < "$OUT") lines."

rm -rf "$TMP"
