#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <domain> [subdomains.txt]"
    echo "  Aggregates subdomains from multiple passive sources incl. API-based ones."
    exit 1
fi

DOMAIN="$1"
SUBDOMAINS_FILE="${2:-subdomains.txt}"

touch "$SUBDOMAINS_FILE"

TMP="/tmp/passivesources_$$"
mkdir -p "$TMP"
RAW="$TMP/raw.txt"
> "$RAW"

echo "[*] Target: $DOMAIN"

echo "[*] subfinder (built-in passive sources)..."
if command -v subfinder >/dev/null 2>&1; then
    timeout 120 subfinder -d "$DOMAIN" -t 20 -silent 2>/dev/null >> "$RAW"
    sleep 2
fi

echo "[*] amass passive..."
if command -v amass >/dev/null 2>&1; then
    timeout 180 amass enum -passive -d "$DOMAIN" 2>/dev/null >> "$RAW"
    sleep 2
fi

echo "[*] assetfinder..."
if command -v assetfinder >/dev/null 2>&1; then
    timeout 60 assetfinder --subs-only "$DOMAIN" 2>/dev/null >> "$RAW"
    sleep 2
fi

echo "[*] crt.sh certificate transparency..."
timeout 30 curl -s --max-time 25 "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null \
    | jq -r '.[].name_value' 2>/dev/null | tr '\n' '\n' \
    | sed 's/\*\.//' | sed '/^$/d' >> "$RAW"

echo "[*] AlienVault OTX..."
timeout 25 curl -s --max-time 20 "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" 2>/dev/null \
    | jq -r '.passive_dns[].hostname' 2>/dev/null | grep -F ".$DOMAIN" >> "$RAW"

echo "[*] Anubis..."
timeout 25 curl -s --max-time 20 "https://jldc.me/anubis/subdomains/$DOMAIN" 2>/dev/null \
    | jq -r '.[]' 2>/dev/null | grep -F ".$DOMAIN" >> "$RAW"

echo "[*] RapidDNS..."
timeout 25 curl -s --max-time 20 "https://rapiddns.io/subdomain/$DOMAIN?full=1" 2>/dev/null \
    | grep -oE "[a-zA-Z0-9._-]+\.$DOMAIN" | sort -u >> "$RAW"

echo "[*] Shodan (domain DNS) if API..."
if command -v shodan >/dev/null 2>&1; then
    timeout 30 shodan domain "$DOMAIN" 2>/dev/null | awk '{print $1}' | grep -F ".$DOMAIN" >> "$RAW"
fi

echo "[*] SecurityTrails (if API key)..."
if [ -n "$SECURITYTRAILS_API_KEY" ]; then
    timeout 25 curl -s --max-time 20 -H "APIKEY: $SECURITYTRAILS_API_KEY" \
        "https://api.securitytrails.com/v1/domain/$DOMAIN/subdomains" 2>/dev/null \
        | jq -r '.subdomains[]' 2>/dev/null | sed "s/$/.$DOMAIN/" >> "$RAW"
fi

echo "[*] Merging & validating..."
sort -u "$RAW" | grep -E "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$" \
    | sort -u > "$TMP/clean.txt"

cat "$SUBDOMAINS_FILE" >> "$TMP/clean.txt"
sort -u "$TMP/clean.txt" -o "$TMP/clean.txt"

NEW=$(comm -23 "$TMP/clean.txt" <(sort -u "$SUBDOMAINS_FILE"))
NEW_COUNT=$(echo "$NEW" | grep -c ".")

echo "$NEW" >> "$SUBDOMAINS_FILE"
sort -u "$SUBDOMAINS_FILE" -o "$SUBDOMAINS_FILE"

echo "[+] Total subs in $SUBDOMAINS_FILE: $(wc -l < "$SUBDOMAINS_FILE")"
echo "[+] New subs added: $NEW_COUNT"
echo "[+] Run iprecon.sh to resolve IPs and check alive status."

rm -rf "$TMP"
