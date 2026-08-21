#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <domain|subdomains.txt>"
    echo "  Uses CDN range filtering + historical DNS (shodan/censys/crt.sh) +"
    echo "  IP-leaking headers + favicon hash to locate real origin IPs."
    exit 1
fi

INPUT="$1"
TMP="/tmp/originip_$$"
mkdir -p "$TMP"

DOMAINS="$TMP/domains.txt"
> "$DOMAINS"

if [ -f "$INPUT" ]; then
    grep -vE '^\s*$' "$INPUT" | sed 's|^https\?://||;s|/.*$||' | sort -u > "$DOMAINS"
else
    echo "$INPUT" > "$DOMAINS"
fi

APEX=$(sort -u "$DOMAINS" | head -1 | sed 's/^[^.a-z]*\.//' )

IPS_OUT="origin_ips.txt"
REASON_OUT="origin_reasons.txt"
CDN_FILE="$TMP/cdn_ranges.txt"

> "$IPS_OUT"
> "$REASON_OUT"

IP_REGEX="([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"

echo "[*] Fetching CDN/cloud ranges..."
for url in \
    "https://www.cloudflare.com/ips-v4" \
    "https://cloudflare.com/ips-v6" \
    "https://api.fastly.com/public-ip-list"; do
    curl -s --max-time 15 "$url" >> "$CDN_FILE" 2>/dev/null
done
curl -s --max-time 15 "https://ip-ranges.amazonaws.com/ip-ranges.json" \
    | grep -oE '"ip_prefix"[: ]+"[0-9./]+"' \
    | grep -oE "$IP_REGEX[0-9/]+" >> "$CDN_FILE" 2>/dev/null

echo "[*] Checking IP-leaking HTTP headers on live hosts..."
echo "[*] Checking IP-leaking HTTP headers on live hosts (sequential)..."
while IFS= read -r h; do
    h=$(echo "$h" | tr -d '[:space:]')
    [ -z "$h" ] && continue
    curl -sk --max-time 10 "https://$h" -A "Mozilla/5.0" -D - -o /dev/null 2>/dev/null | \
        grep -iE "^(x-real-ip|x-forwarded-for|x-origin-ip|x-backend-ip|cf-connecting-ip|x-client-ip|via|x-server-ip|server-ip|x-host|x-orig-ip):" | \
        grep -oE "$IP_REGEX"
    sleep 3
done < "$DOMAINS" | sort -u >> "$IPS_OUT"

echo "[*] Certificate transparency hosts (historical)..."
curl -s --max-time 20 "https://crt.sh/?q=%25.$APEX&output=json" 2>/dev/null \
    | jq -r '.[]?.name_value' 2>/dev/null | tr '\n' '\n' | sed 's/\*\.//;s/^ //' \
    | sort -u > "$TMP/crtsubs.txt" 2>/dev/null

echo "[*] Resolving historical/cert subdomains (may include origin hosts)..."
if [ -s "$TMP/crtsubs.txt" ]; then
    timeout 120 dnsx -l "$TMP/crtsubs.txt" -a -resp -r /root/config/resolvers.txt \
        -t 2 -rl 3 -silent 2>/dev/null \
        | grep -oE "$IP_REGEX" >> "$IPS_OUT"
fi

echo "[*] Shodan historical DNS / free lookups..."
while IFS= read -r host; do
    host=$(echo "$host" | tr -d '[:space:]')
    [ -z "$host" ] && continue
    shodan host "$host" 2>/dev/null | grep -oE "$IP_REGEX"
    sleep 5
done < "$DOMAINS" | sort -u >> "$IPS_OUT"

echo "[*] HackerTarget hostsearch (historical)..."
while IFS= read -r host; do
    host=$(echo "$host" | tr -d '[:space:]')
    [ -z "$host" ] && continue
    curl -s --max-time 12 "https://api.hackertarget.com/hostsearch/?q=$host" 2>/dev/null \
        | grep -oE "$IP_REGEX"
    sleep 10
done < "$DOMAINS" | sort -u >> "$IPS_OUT"

echo "[*] SecurityTrails history (if key set)..."
if [ -n "$SECURITYTRAILS_API_KEY" ]; then
    head -20 "$DOMAINS" | while IFS= read -r host; do
        host=$(echo "$host" | tr -d '[:space:]')
        [ -z "$host" ] && continue
        curl -s --max-time 12 -H "APIKEY: $SECURITYTRAILS_API_KEY" \
            "https://api.securitytrails.com/v1/history/$host/dns/a" 2>/dev/null \
            | grep -oE "$IP_REGEX"
        sleep 5
    done | sort -u >> "$IPS_OUT"
fi

echo "[*] Favicon-hash search for origin IPs (shodan host correlation)..."
if command -v shodan >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    head -5 "$DOMAINS" | while IFS= read -r host; do
        host=$(echo "$host" | tr -d '[:space:]')
        [ -z "$host" ] && continue
        FAVICON_HASH=$(python3 -c "
import mmh3,requests,codecs
try:
    r=requests.get('https://$host/favicon.ico',timeout=8).content
    print(mmh3.hash(codecs.encode(r,'base64')))
except Exception:
    print('')" 2>/dev/null)
        if [ -n "$FAVICON_HASH" ]; then
            # shodan host lookups of known cert names may correlate; free tier blocks search
            shodan host "favicon.hash:$FAVICON_HASH" 2>/dev/null | grep -oE "$IP_REGEX"
        fi
        sleep 5
    done | sort -u >> "$IPS_OUT"
fi

echo "[*] Filtering out CDN/cloud/private IPs..."
python3 - "$CDN_FILE" "$IPS_OUT" "$IPS_OUT" "$REASON_OUT" << 'PYEOF'
import ipaddress
import re
import sys

cdn_file, in_file, out_file, reason_file = sys.argv[1:5]

def clean(ip):
    m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ip)
    return m.group(1) if m else ''

cdn_nets = []
try:
    with open(cdn_file) as f:
        for line in f:
            m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line)
            if m:
                try: cdn_nets.append(ipaddress.ip_network(m.group(1), strict=False))
                except ValueError: pass
except FileNotFoundError:
    pass

priv = [ipaddress.ip_network(x) for x in
        ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','0.0.0.0/8',
         '169.254.0.0/16','100.64.0.0/10')]

def bad(ip):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return True
    if any(a in n for n in priv): return True
    if any(a in n for n in cdn_nets): return True
    return False

seen = set()
with open(in_file) as f:
    for line in f:
        ip = clean(line)
        if ip and not bad(ip) and ip not in seen:
            seen.add(ip)

with open(out_file, 'w') as f:
    for ip in sorted(seen):
        f.write(ip + '\n')

with open(reason_file, 'w') as f:
    f.write(f'Likely origin IPs: {len(seen)}\n')

print(f'[+] Likely origin IPs (after CDN filter): {len(seen)}')
PYEOF

echo "[+] Done."
echo "[+] origin_ips.txt: $(wc -l < "$IPS_OUT") candidate real IPs"
echo "[+] Run nmapscan.sh on each to confirm."

rm -rf "$TMP"
