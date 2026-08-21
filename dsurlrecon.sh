#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <domain> [-l subdomains.txt] [dir_wordlist.txt]"
    echo "  Aggregates URLs from archives (gau/wayback/waymore/paramspider),"
    echo "  crawlers (hakrawler/gospider/katana), finders (assetfinder/"
    echo "  xnLinkFinder/urlfinder) and optional directory bruteforce."
    echo "  All results are appended/deduped into urls.txt."
    exit 1
fi

DOMAIN="$1"
SUBDOMAINS_FILE=""
DIR_WORDLIST=""

# parse: dsurlrecon <domain> [-l subdomains.txt] [dir_wordlist.txt]
if [ "$2" = "-l" ] && [ -n "$3" ]; then
    SUBDOMAINS_FILE="$3"
    DIR_WORDLIST="${4:-}"
else
    DIR_WORDLIST="${2:-}"
fi

URLS_OUT="urls.txt"
JS_OUT="js.txt"
PARAMS_OUT="parameters.txt"
CURLS_OUT="curls.txt"
FIND_OUT="findurls.txt"
NEW_OUT="new_urls.txt"

touch "$URLS_OUT"
> "$JS_OUT"
> "$PARAMS_OUT"
> "$CURLS_OUT"
> "$FIND_OUT"
> "$NEW_OUT"

TARGETS="/tmp/urlrel_targets_$$.txt"

> "$TARGETS"

if [ -n "$SUBDOMAINS_FILE" ] && [ -f "$SUBDOMAINS_FILE" ]; then
    grep -vE '^\s*$' "$SUBDOMAINS_FILE" | sed 's|^https\?://||;s|/.*$||' | sort -u > "$TARGETS"
else
    echo "$DOMAIN" > "$TARGETS"
fi

echo "[*] Total targets: $(wc -l < "$TARGETS")"

while IFS= read -r TARGET; do
    echo "[*] Gathering archive URLs for: $TARGET"

    PER_TARGET="/tmp/urlrel_target_$$.txt"
    > "$PER_TARGET"

    gau "$TARGET" --threads 1 --timeout 10 --retries 2 2>/dev/null >> "$PER_TARGET"
    sleep 3

    waybackurls "$TARGET" 2>/dev/null >> "$PER_TARGET"
    sleep 3

    if command -v waymore >/dev/null 2>&1; then
        waymore -i "$TARGET" -n -oU "/tmp/waymore_out_$$" -mode U 2>/dev/null
        cat /tmp/waymore_out_$$/* 2>/dev/null >> "$PER_TARGET"
        sleep 3
    fi

    paramspider -d "$TARGET" --quiet 2>/dev/null | grep -oE "https?://[^ ]+" >> "$PER_TARGET"
    sleep 4

    echo "[*] Crawling (hakrawler/gospider/katana): $TARGET"
    echo "$TARGET" | hakrawler -depth 3 -subs -u 2>/dev/null | grep -oE "https?://[^ ]+" >> "$PER_TARGET"
    sleep 3
    gospider -s "$TARGET" -d 3 -t 1 -c 1 -w -a --no-redirect -q 2>/dev/null \
        | grep -oE "https?://[^ ]+" >> "$PER_TARGET"
    sleep 3
    if command -v katana >/dev/null 2>&1; then
        katana -u "$TARGET" -d 3 -jc -w 1 -rl 5 -timeout 10 -silent 2>/dev/null >> "$PER_TARGET"
        sleep 3
    fi

    echo "[*] Finding URLs (assetfinder/xnLinkFinder/urlfinder): $TARGET"
    assetfinder --subs-only "$TARGET" 2>/dev/null | sed "s/^/https:\/\//" >> "$PER_TARGET"
    sleep 3
    xnLinkFinder -i "https://$TARGET" -d "$TARGET" -o cli 2>/dev/null | grep -oE "https?://[^ ]+" >> "$PER_TARGET"
    sleep 3
    urlfinder -d "$TARGET" -all -silent 2>/dev/null | grep -oE "https?://[^ ]+" >> "$PER_TARGET"
    sleep 4

    # Flush this target's URLs into urls.txt incrementally (deduped) so that
    # even if the run is interrupted, urls.txt is never empty.
    grep -oE "https?://[^ ]+" "$PER_TARGET" 2>/dev/null | sed 's/[),;]*$//' \
        | grep -vE "\.(jpg|jpeg|png|gif|svg|ico|bmp|webp|woff|woff2|ttf|eot|css)(\?.*)?$" \
        >> "$URLS_OUT"
    sort -u "$URLS_OUT" -o "$URLS_OUT"
    rm -f "$PER_TARGET"
    echo "    [progress] urls.txt now has $(wc -l < "$URLS_OUT") unique URLs"

done < "$TARGETS"

echo "[*] Validating with httpx and splitting js/params..."
sort -u "$URLS_OUT" > /tmp/urlrel_deduped_$$.txt

httpx -l /tmp/urlrel_deduped_$$.txt \
    -threads 2 \
    -rate-limit 10 \
    -timeout 10 \
    -silent \
    -mc 200,201,301,302,307,401,403 \
    2>/dev/null > /tmp/urlrel_httpx_$$.txt

grep -oE "https?://[^ ]+" /tmp/urlrel_httpx_$$.txt | sed 's/ \[[0-9]*\]$//' | sort -u > /tmp/urlrel_live_$$.txt

cp /tmp/urlrel_live_$$.txt "$CURLS_OUT"
sort -u "$CURLS_OUT" -o "$CURLS_OUT"

grep -iE "\.js(\?.*)?$" /tmp/urlrel_live_$$.txt > "$JS_OUT"
grep -iE "\.js(\?.*)?$" "$URLS_OUT" >> "$JS_OUT"
sort -u "$JS_OUT" -o "$JS_OUT"

grep -E "\?[^=]+=|&[^=]+=" "$URLS_OUT" > "$PARAMS_OUT"

cp /tmp/urlrel_live_$$.txt "$NEW_OUT"
sort -u "$NEW_OUT" -o "$NEW_OUT"
echo "[*] new_urls.txt (freshly gathered): $(wc -l < "$NEW_OUT")"

echo "[*] Optional directory bruteforce (main domain only, once)..."
if [ -n "$DIR_WORDLIST" ] && [ -f "$DIR_WORDLIST" ] && [ -s "$DIR_WORDLIST" ]; then
    BURL="burl.txt"
    > "$BURL"
    # Run dir-brute ONCE against the MAIN domain only (never looping per subdomain).
    MAIN_HOST="$(echo "$DOMAIN" | sed 's|^https\?://||;s|/.*$||')"
    FFUF_DIR_MAXTIME=600   # hard cap (10 min) so ffuf can never freeze the pipeline
    FFUF_DIR_RATE=30

    echo "[*] ffuf dir scan: $MAIN_HOST (wordlist=$(basename "$DIR_WORDLIST"), maxtime=${FFUF_DIR_MAXTIME}s)"
    if command -v ffuf >/dev/null 2>&1; then
        timeout $((FFUF_DIR_MAXTIME + 30)) ffuf -u "https://$MAIN_HOST/FUZZ" \
            -w "$DIR_WORDLIST" -t 3 -rate "$FFUF_DIR_RATE" -timeout 10 \
            -maxtime "$FFUF_DIR_MAXTIME" \
            -mc 200,201,204,301,302,307,401,403 \
            -o "/tmp/urlrel_ffuf_$$.json" -of json -s > /dev/null 2>&1
        if [ -f /tmp/urlrel_ffuf_$$.json ]; then
            python3 - "$$" << 'PYEOF'
import json, sys
try:
    with open(f'/tmp/urlrel_ffuf_{sys.argv[1]}.json') as f:
        data = json.load(f)
    with open('burl.txt', 'a') as out:
        for r in data.get('results', []):
            if r.get('url'):
                out.write(f"{r['url']} [{r.get('status','')}]\n")
except FileNotFoundError:
    pass
PYEOF
            rm -f /tmp/urlrel_ffuf_$$.json
        fi
    fi

    if [ -f "$BURL" ] && [ -s "$BURL" ]; then
        grep -oE "https?://[^ ]+" "$BURL" | sed 's/ \[[0-9]*\]$//' | sort -u >> "$URLS_OUT"
        sort -u "$URLS_OUT" -o "$URLS_OUT"
    fi
fi

echo "[+] Done."
echo "[+] urls.txt: $(wc -l < "$URLS_OUT") URLs"
echo "[+] js.txt: $(wc -l < "$JS_OUT") JS files"
echo "[+] parameters.txt: $(wc -l < "$PARAMS_OUT") URLs with parameters"
echo "[+] curls.txt: $(wc -l < "$CURLS_OUT") crawled/found links"
echo "[+] burl.txt present: $([ -f burl.txt ] && echo yes || echo no)"

{
    echo ""
    echo "========================================================================="
    echo " [dsurlrecon] URL GATHERING $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================================================="
    echo "[*] urls.txt       : $(wc -l < "$URLS_OUT" | tr -d ' ')"
    echo "[*] js.txt         : $(wc -l < "$JS_OUT" | tr -d ' ')"
    echo "[*] parameters.txt : $(wc -l < "$PARAMS_OUT" | tr -d ' ')"
    echo "[*] new_urls.txt (fresh): $(wc -l < "$NEW_OUT" | tr -d ' ')"
    echo ""
} >> fullreport.txt 2>/dev/null

rm -rf /tmp/waymore_out_$$ /tmp/urlrel_targets_$$.txt \
    /tmp/urlrel_deduped_$$.txt /tmp/urlrel_httpx_$$.txt /tmp/urlrel_live_$$.txt
