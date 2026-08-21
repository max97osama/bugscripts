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

FFUF_RATE=20
FFUF_THREADS=3
FFUF_MAXTIME_PER_DOMAIN=1800

ESTIMATED_SECONDS=$(( WORDLIST_LINES / FFUF_RATE ))
if [ "$ESTIMATED_SECONDS" -gt "$FFUF_MAXTIME_PER_DOMAIN" ]; then
    echo "[!] Wordlist would take ~$((ESTIMATED_SECONDS / 60)) minutes per domain at current rate."
    echo "[!] Capping each domain's ffuf run to $((FFUF_MAXTIME_PER_DOMAIN / 60)) minutes with -maxtime."
fi

SUBS_OUT="subs.txt"
CLEANED_OUT="cleanedsubs.txt"
VALID_OUT="validsubs.txt"

touch "$SUBS_OUT" "$CLEANED_OUT" "$VALID_OUT"

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
    timeout $((FFUF_MAXTIME_PER_DOMAIN + 60)) ffuf -u "https://FUZZ.$DOMAIN" \
        -w "$WORDLIST" \
        -t "$FFUF_THREADS" \
        -rate "$FFUF_RATE" \
        -timeout 5 \
        -maxtime "$FFUF_MAXTIME_PER_DOMAIN" \
        -se \
        -mc 200,301,302,403 \
        -o "$FFUF_JSON" \
        -of json \
        -s 2>/dev/null

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
