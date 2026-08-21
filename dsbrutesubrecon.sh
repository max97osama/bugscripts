#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <domain|domains.txt> <wordlist.txt> <subdomains.txt>"
    exit 1
fi

INPUT="$1"
WORDLIST="$2"
SUBDOMAINS_FILE="$3"

touch "$SUBDOMAINS_FILE"

DOMAINS_LIST="/tmp/bs_domains_$$.txt"
> "$DOMAINS_LIST"

if [ -f "$INPUT" ]; then
    while IFS= read -r line; do
        line=$(echo "$line" | tr -d '[:space:]')
        [ -z "$line" ] && continue
        echo "$line" >> "$DOMAINS_LIST"
    done < "$INPUT"
else
    echo "$INPUT" >> "$DOMAINS_LIST"
fi

sort -u "$DOMAINS_LIST" -o "$DOMAINS_LIST"

TOTAL_DOMAINS=$(wc -l < "$DOMAINS_LIST")
WORDLIST_LINES=$(wc -l < "$WORDLIST")

echo "[*] Total domains to process: $TOTAL_DOMAINS"
echo "[*] Wordlist size: $WORDLIST_LINES lines"

# Safe, low-rate defaults for the 1-core/1GB VM.
# NOTE: never auto-scale the rate up high - it overloads the VM and the
# process gets stopped (state T), freezing the whole pipeline (seen in the
# field). ffuf runs are capped by -maxtime so they can never hang forever.
FFUF_THREADS=3
FFUF_MAXTIME_PER_DOMAIN=1800
FFUF_RATE=30
FFUF_RATE_MAX=80

if [ "$WORDLIST_LINES" -gt 0 ]; then
    # aim to finish the whole wordlist within 80% of the time cap, but cap the
    # rate at FFUF_RATE_MAX so we never overload the low-resource VM.
    recommended=$(( WORDLIST_LINES * 100 / (FFUF_MAXTIME_PER_DOMAIN * 80) ))
    if [ "$recommended" -gt "$FFUF_RATE" ]; then
        if [ "$recommended" -le "$FFUF_RATE_MAX" ]; then
            FFUF_RATE=$recommended
        else
            FFUF_RATE=$FFUF_RATE_MAX
        fi
    fi
fi

ESTIMATED_SECONDS=$(( WORDLIST_LINES / FFUF_RATE ))
if [ "$ESTIMATED_SECONDS" -gt "$FFUF_MAXTIME_PER_DOMAIN" ] && [ "$WORDLIST_LINES" -gt 250000 ]; then
    echo "[!] Wordlist is very large ($WORDLIST_LINES lines): even at rate=$FFUF_RATE it needs ~$((ESTIMATED_SECONDS / 60)) min/domain."
    echo "[!] This is NOT practical on this 1-core VM and was the cause of repeated freezes."
    echo "[!] Strongly recommended: use a trimmed subdomain wordlist (< 200k lines)."
    echo "[!] ffuf will be capped at $((FFUF_MAXTIME_PER_DOMAIN / 60)) min via -maxtime and will NOT freeze."
fi

SUBS_OUT="subs.txt"
CLEANED_OUT="cleanedsubs.txt"
VALID_OUT="validsubs.txt"

touch "$SUBS_OUT" "$CLEANED_OUT" "$VALID_OUT"

# Guard against absurdly large wordlists: trim to a practical max so ffuf
# actually completes within the time cap instead of spinning for hours.
FFUF_TRIM_MAX=200000
FFUF_WORDLIST="$WORDLIST"
if [ "$WORDLIST_LINES" -gt "$FFUF_TRIM_MAX" ]; then
    FFUF_WORDLIST="/tmp/bs_trimmed_$$.txt"
    echo "[*] Wordlist too large ($WORDLIST_LINES lines) for this VM; trimming to $FFUF_TRIM_MAX lines for ffuf."
    head -n "$FFUF_TRIM_MAX" "$WORDLIST" > "$FFUF_WORDLIST"
fi

FFUF_OUT="/tmp/ffuf_subs_$$.txt"
KNOCK_OUT="/tmp/knock_subs_$$.txt"
ALTERX_OUT="/tmp/alterx_subs_$$.txt"
ALL_RAW="/tmp/all_raw_$$.txt"
FFUF_JSON="/tmp/ffuf_raw_$$.json"

> "$ALL_RAW"

while IFS= read -r DOMAIN; do
    echo "[*] Starting subdomain bruteforce for: $DOMAIN"

    > "$FFUF_OUT"
    > "$KNOCK_OUT"
    > "$ALTERX_OUT"

    echo "[*] Running ffuf subdomain bruteforce on $DOMAIN (rate=$FFUF_RATE, threads=$FFUF_THREADS, maxtime=${FFUF_MAXTIME_PER_DOMAIN}s)..."
    # Redirect stdout/stderr fully to avoid writing to a detached/blocked pty
    # (a stopped T process was seen when running inside a detached screen).
    timeout $((FFUF_MAXTIME_PER_DOMAIN + 60)) ffuf -u "https://FUZZ.$DOMAIN" \
        -w "$FFUF_WORDLIST" \
        -t "$FFUF_THREADS" \
        -rate "$FFUF_RATE" \
        -timeout 5 \
        -maxtime "$FFUF_MAXTIME_PER_DOMAIN" \
        -se \
        -mc 200,301,302,403 \
        -o "$FFUF_JSON" \
        -of json \
        -s > /dev/null 2>&1

    if [ -f "$FFUF_JSON" ]; then
        python3 -c "
import json
with open('$FFUF_JSON') as f:
    data = json.load(f)
for r in data.get('results', []):
    host = r.get('input', {}).get('FUZZ', '')
    if host:
        print(f'{host}.$DOMAIN')
" > "$FFUF_OUT" 2>/dev/null
        rm -f "$FFUF_JSON"
    else
        echo "[-] ffuf produced no output for $DOMAIN (timed out or found nothing)."
    fi

    sleep 3

    echo "[*] Running knockpy on $DOMAIN..."
    timeout 300 knockpy "$DOMAIN" --recon --no-http 2>/dev/null | \
        grep -oE "[a-zA-Z0-9._-]+\.$DOMAIN" > "$KNOCK_OUT"

    sleep 3

    echo "[*] Running alterx permutation on $DOMAIN..."
    grep "$DOMAIN" "$SUBDOMAINS_FILE" 2>/dev/null > /tmp/bs_domain_subs_$$.txt
    if [ -s /tmp/bs_domain_subs_$$.txt ]; then
        timeout 120 alterx -l /tmp/bs_domain_subs_$$.txt \
            -o "$ALTERX_OUT" \
            -enrich 2>/dev/null
    fi
    rm -f /tmp/bs_domain_subs_$$.txt

    sleep 2

    echo "[*] Merging candidates for $DOMAIN..."
    cat "$SUBDOMAINS_FILE" "$FFUF_OUT" "$KNOCK_OUT" "$ALTERX_OUT" 2>/dev/null | \
        grep -E "^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$" | \
        grep "$DOMAIN" | \
        sort -u >> "$ALL_RAW"

done < "$DOMAINS_LIST"

sort -u "$ALL_RAW" -o "$ALL_RAW"

echo "[*] Total unique candidates across all domains: $(wc -l < "$ALL_RAW")"

NEW_CANDIDATES=$(comm -23 "$ALL_RAW" <(sort -u "$SUBDOMAINS_FILE"))
NEW_COUNT=$(echo "$NEW_CANDIDATES" | grep -c ".")

echo "$NEW_CANDIDATES" >> "$SUBDOMAINS_FILE"
sort -u "$SUBDOMAINS_FILE" -o "$SUBDOMAINS_FILE"

echo "$NEW_CANDIDATES" >> "$CLEANED_OUT"
sort -u "$CLEANED_OUT" -o "$CLEANED_OUT"

echo "[+] $NEW_COUNT new subdomains added to $SUBDOMAINS_FILE"
echo "[+] brutesubrecon does not resolve/probe here — run iprecon.sh next to resolve IPs and check alive status."
echo "[+] Output files: $CLEANED_OUT appended, $SUBDOMAINS_FILE appended"

rm -f "$FFUF_OUT" "$KNOCK_OUT" "$ALTERX_OUT" "$ALL_RAW" "$DOMAINS_LIST"
[ -n "$FFUF_WORDLIST" ] && [ -f "$FFUF_WORDLIST" ] && [ "$FFUF_WORDLIST" != "$WORDLIST" ] && rm -f "$FFUF_WORDLIST"
