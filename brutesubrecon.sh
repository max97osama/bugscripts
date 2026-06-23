#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <domain> <wordlist.txt> <subdomains.txt>"
    exit 1
fi

DOMAIN="$1"
WORDLIST="$2"
SUBDOMAINS_FILE="$3"

FFUF_OUT="/tmp/ffuf_subs_$$.txt"
KNOCK_OUT="/tmp/knock_subs_$$.txt"
ALTDNS_OUT="/tmp/altdns_subs_$$.txt"
ALL_RAW="/tmp/all_raw_$$.txt"
RESOLVED="/tmp/resolved_$$.txt"
FFUF_JSON="/tmp/ffuf_raw_$$.json"
NEW_SUBS="/tmp/new_subs_$$.txt"
HTTPX_OUT="/tmp/httpx_$$.txt"
DNSX_OUT="/tmp/dnsx_$$.txt"

SUBS_OUT="subs.txt"
CLEANED_OUT="cleanedsubs.txt"
IPS_OUT="ips.txt"
VALID_OUT="validsubs.txt"

> "$SUBS_OUT"
> "$CLEANED_OUT"
> "$IPS_OUT"
> "$VALID_OUT"

echo "[*] Starting subdomain recon for: $DOMAIN"

echo "[*] Running ffuf subdomain bruteforce..."
ffuf -u "https://FUZZ.$DOMAIN" \
    -w "$WORDLIST" \
    -t 1 \
    -rate 5 \
    -timeout 10 \
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
fi

sleep 5

echo "[*] Running knockpy..."
knockpy "$DOMAIN" --recon --no-http 2>/dev/null | \
    grep -oE "[a-zA-Z0-9._-]+\.$DOMAIN" > "$KNOCK_OUT"

sleep 5

echo "[*] Running altdns permutation..."
altdns -i "$SUBDOMAINS_FILE" \
    -o "$ALTDNS_OUT" \
    -w "$WORDLIST" 2>/dev/null

sleep 3

echo "[*] Merging all candidates..."
cat "$SUBDOMAINS_FILE" "$FFUF_OUT" "$KNOCK_OUT" "$ALTDNS_OUT" 2>/dev/null | \
    grep -E "^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$" | \
    grep "$DOMAIN" | \
    sort -u > "$ALL_RAW"

echo "[*] Total unique candidates: $(wc -l < "$ALL_RAW")"

echo "[*] Resolving with dnsx..."
dnsx -l "$ALL_RAW" \
    -t 1 \
    -rl 5 \
    -o "$RESOLVED" \
    -silent 2>/dev/null

echo "[*] Running dnsx for IP and hostname info..."
dnsx -l "$RESOLVED" \
    -t 1 \
    -rl 5 \
    -a \
    -resp \
    -silent \
    2>/dev/null > "$DNSX_OUT"

sleep 3

echo "[*] Running httpx for status codes..."
httpx -l "$RESOLVED" \
    -threads 1 \
    -rate-limit 5 \
    -timeout 10 \
    -status-code \
    -silent \
    2>/dev/null > "$HTTPX_OUT"

sleep 3

echo "[*] Building output files..."

python3 - <<PYEOF
import re

httpx_map = {}
with open('$HTTPX_OUT', 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            url = parts[0].replace('https://','').replace('http://','').rstrip('/')
            code = parts[1].strip('[]')
            httpx_map[url] = code

dnsx_map = {}
with open('$DNSX_OUT', 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        sub = line.split()[0] if line.split() else ''
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        names = re.findall(r'\[([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})\]', line)
        names = [n for n in names if not re.match(r'^\d+\.\d+\.\d+\.\d+$', n)]
        ip = ips[0] if ips else '0.0.0.0'
        name = names[-1] if names else sub
        dnsx_map[sub] = (ip, name)

with open('$RESOLVED', 'r') as f:
    subs = [line.strip() for line in f if line.strip()]

subs_out = open('$SUBS_OUT', 'w')
cleaned_out = open('$CLEANED_OUT', 'w')
ips_out = open('$IPS_OUT', 'w')
valid_out = open('$VALID_OUT', 'w')

all_ips = set()

for sub in subs:
    code = httpx_map.get(sub, 'N/A')
    ip, name = dnsx_map.get(sub, ('0.0.0.0', sub))
    status_text = 'OK' if code == '200' else code
    subs_out.write(f'{sub} {code} {status_text} {ip} {name}\n')
    cleaned_out.write(f'{sub}\n')
    if ip != '0.0.0.0':
        all_ips.add(ip)
    if code == '200':
        valid_out.write(f'{sub}\n')

for ip in sorted(all_ips):
    ips_out.write(f'{ip}\n')

subs_out.close()
cleaned_out.close()
ips_out.close()
valid_out.close()

print(f'[+] subs.txt entries: {len(subs)}')
print(f'[+] validsubs.txt (200 OK): {sum(1 for s in subs if httpx_map.get(s,"") == "200")}')
print(f'[+] ips.txt unique IPs: {len(all_ips)}')
PYEOF

EXISTING=$(sort "$SUBDOMAINS_FILE" | uniq)
NEW=$(comm -23 <(sort "$CLEANED_OUT") <(sort "$SUBDOMAINS_FILE"))
NEW_COUNT=$(echo "$NEW" | grep -c ".")

echo "$NEW" >> "$SUBDOMAINS_FILE"
sort -u "$SUBDOMAINS_FILE" -o "$SUBDOMAINS_FILE"

echo "[+] $NEW_COUNT new subdomains added to $SUBDOMAINS_FILE"
echo "[+] Output files: $SUBS_OUT | $CLEANED_OUT | $IPS_OUT | $VALID_OUT"

rm -f "$FFUF_OUT" "$KNOCK_OUT" "$ALTDNS_OUT" "$ALL_RAW" "$RESOLVED" \
    "$NEW_SUBS" "$HTTPX_OUT" "$DNSX_OUT"
