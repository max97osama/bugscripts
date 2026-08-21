#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <subdomains.txt>"
    exit 1
fi

INPUT="$1"
ACTIVE_OUT="activesubs.txt"
IPS_OUT="ips.txt"
ORIGIN_OUT="origin_ips.txt"

touch "$ACTIVE_OUT" "$IPS_OUT" "$ORIGIN_OUT"

TMP="/tmp/iprecon_$$"
mkdir -p "$TMP"
RAW_IPS="$TMP/raw_ips.txt"
ALIVE_HOSTS="$TMP/alive_hosts.txt"
RESOLVED="$TMP/resolved.txt"
CDN_FILE="$TMP/cdn_ranges.txt"
NON_CDN_IP="$TMP/non_cdn_ip.txt"

> "$RAW_IPS"
> "$ALIVE_HOSTS"
> "$RESOLVED"
> "$CDN_FILE"
> "$NON_CDN_IP"

IP_REGEX="([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"

echo "[*] Reading subdomains from: $INPUT"
TOTAL=$(wc -l < "$INPUT")
echo "[*] Total subdomains to process: $TOTAL"

echo "[*] Fetching CDN/cloud IP ranges..."
for url in \
    "https://www.cloudflare.com/ips-v4" \
    "https://platform.cloudflare.com/ips-v4" \
    "https://raw.githubusercontent.com/Azure/Azure-Public-IP-Ranges/refs/heads/master/ServiceTags_Public.json" \
    "https://api.fastly.com/public-ip-list"; do
    curl -s --max-time 15 "$url" >> "$CDN_FILE" 2>/dev/null
done

curl -s --max-time 15 "https://ip-ranges.amazonaws.com/ip-ranges.json" \
    | grep -oE '"ip_prefix": ?"[^"]+"' \
    | grep -oE "$IP_REGEX[0-9/]+" >> "$CDN_FILE" 2>/dev/null

echo "[*] Checking alive subdomains with httpx (low concurrency)..."
httpx -l "$INPUT" \
    -threads 2 \
    -rate-limit 5 \
    -timeout 10 \
    -status-code \
    -no-color \
    -silent \
    2>/dev/null | grep -oE "https?://[^ ]+" | \
    sed -E 's|^https?://||;s|/.*$||' | \
    sort -u >> "$ALIVE_HOSTS"

if [ ! -s "$ALIVE_HOSTS" ]; then
    echo "[-] No alive subdomains found by httpx, falling back to full input list."
    cp "$INPUT" "$ALIVE_HOSTS"
fi

sort -u "$ALIVE_HOSTS" -o "$ALIVE_HOSTS"
echo "[+] Alive/potential subdomains: $(wc -l < "$ALIVE_HOSTS")"

echo "[*] Resolving IPs with dnsx using multiple public resolvers..."
cat > "$TMP/resolvers.txt" << 'RESOLVERS'
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
76.76.2.0
76.76.10.0
1.1.1.2
8.20.247.20
94.140.14.14
RESOLVERS

dnsx -l "$ALIVE_HOSTS" \
    -t 2 \
    -rl 5 \
    -a \
    -aaaa \
    -resp \
    -r "$TMP/resolvers.txt" \
    -silent \
    2>/dev/null > "$RESOLVED"

echo "[*] dnsx resolved lines: $(wc -l < "$RESOLVED")"

echo "[*] Querying HackerTarget hostsearch for candidate IPs (sequential)..."
while IFS= read -r host; do
    host=$(echo "$host" | tr -d '[:space:]')
    [ -z "$host" ] && continue
    curl -s --max-time 12 \
        "https://api.hackertarget.com/hostsearch/?q=$host" \
        2>/dev/null | grep -oE "$IP_REGEX" >> "$RAW_IPS"
    sleep 10
done < "$ALIVE_HOSTS"

echo "[*] Querying crt.sh certificate transparency for historical hostnames..."
curl -s --max-time 20 \
    "https://crt.sh/?q=%25.$(head -1 "$ALIVE_HOSTS" | sed 's/^\*\.//;s/^www\.//')&output=json" \
    2>/dev/null | grep -oiE '(common_name|name_value)[^,}]*' >> "$TMP/crt_raw.txt" 2>/dev/null

echo "[*] Checking for IP-leaking HTTP headers (X-Real-IP, X-Forwarded-For, Origin-IP) on alive hosts..."
while IFS= read -r h; do
    h=$(echo "$h" | tr -d '[:space:]')
    [ -z "$h" ] && continue
    curl -sk --max-time 10 "https://$h" \
        -A "Mozilla/5.0" -D - -o /dev/null 2>/dev/null | \
        grep -iE "^(x-real-ip|x-forwarded-for|x-origin-ip|x-backend-ip|cf-connecting-ip|x-client-ip|via|x-server-ip|server-ip|x-host|x-orig-ip):" | \
        grep -oE "$IP_REGEX"
    sleep 3
done < "$ALIVE_HOSTS" | sort -u >> "$RAW_IPS"

echo "[*] Searching SecurityTrails historical DNS (if API key set)..."
if [ -n "$SECURITYTRAILS_API_KEY" ]; then
    head -20 "$ALIVE_HOSTS" | grep -vE '^\*\.' | while IFS= read -r host; do
        host=$(echo "$host" | tr -d '[:space:]')
        [ -z "$host" ] && continue
        curl -s --max-time 12 \
            -H "APIKEY: $SECURITYTRAILS_API_KEY" \
            "https://api.securitytrails.com/v1/history/$host/dns/a" \
            2>/dev/null | grep -oE "$IP_REGEX"
        sleep 5
    done | sort -u >> "$RAW_IPS"
else
    echo "[-] SECURITYTRAILS_API_KEY not set, skipping historical DNS lookup."
fi

echo "[*] Shodan historical DNS / host correlation (if API)..."
if command -v shodan >/dev/null 2>&1; then
    head -20 "$ALIVE_HOSTS" | while IFS= read -r host; do
        host=$(echo "$host" | tr -d '[:space:]')
        [ -z "$host" ] && continue
        shodan host "$host" 2>/dev/null | grep -oE "$IP_REGEX"
        sleep 5
    done | sort -u >> "$RAW_IPS"
else
    echo "[-] shodan CLI not found, skipping shodan correlation."
fi

echo "[*] Favicon-hash origin correlation (if shodan + mmh3 available)..."
if command -v shodan >/dev/null 2>&1 && python3 -c "import mmh3" 2>/dev/null; then
    head -5 "$ALIVE_HOSTS" | while IFS= read -r host; do
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
            shodan host "favicon.hash:$FAVICON_HASH" 2>/dev/null | grep -oE "$IP_REGEX"
        fi
        sleep 5
    done | sort -u >> "$RAW_IPS"
fi

echo "[*] Separating CDN vs likely-origin IPs..."
python3 - "$CDN_FILE" "$RESOLVED" "$RAW_IPS" "$NON_CDN_IP" "$ORIGIN_OUT" "$IPS_OUT" << 'PYEOF'
import ipaddress
import re
import sys

cdn_file, resolved_file, raw_ips_file, non_cdn_out, origin_out, ips_out = sys.argv[1:7]

IP_OK = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

def clean_ip(s):
    s = s.strip()
    if s.startswith('*.'):
        return ''
    m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', s)
    return m.group(1) if m else ''

cdn_nets = []
with open(cdn_file, 'r', errors='ignore') as f:
    for line in f:
        m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line)
        if m:
            try:
                cdn_nets.append(ipaddress.ip_network(m.group(1), strict=False))
            except ValueError:
                continue
        else:
            ip = clean_ip(line)
            if ip:
                try:
                    cdn_nets.append(ipaddress.ip_network(ip + '/32', strict=False))
                except ValueError:
                    continue

private_nets = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('100.64.0.0/10'),
]

def bad_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if any(ip in n for n in private_nets):
        return True
    for n in cdn_nets:
        if ip in n:
            return True
    return False

all_ips = set()
from_subs = {}
for src in (resolved_file, raw_ips_file):
    try:
        with open(src, 'r', errors='ignore') as f:
            for line in f:
                if src == resolved_file:
                    parts = line.split()
                    if parts:
                        host = parts[0]
                        for tok in parts:
                            ip = clean_ip(tok)
                            if ip:
                                all_ips.add(ip)
                                from_subs.setdefault(host, set()).add(ip)
                else:
                    for ip in IP_OK.findall(line):
                        ip = clean_ip(ip) or ip
                        if ip:
                            all_ips.add(ip)
    except FileNotFoundError:
        continue

non_cdn = {ip for ip in all_ips if not bad_ip(ip)}

with open(non_cdn_out, 'w') as f:
    for ip in sorted(non_cdn):
        f.write(ip + '\n')

with open(origin_out, 'w') as f:
    for ip in sorted(non_cdn):
        f.write(ip + '\n')

with open(ips_out, 'w') as f:
    for ip in sorted(non_cdn):
        f.write(ip + '\n')

print(f'[+] Total unique IPs resolved: {len(all_ips)}')
print(f'[+] Non-CDN / likely-origin IPs: {len(non_cdn)}')
print(f'[+] Written to {ips_out} and {origin_out}')
PYEOF

echo "[+] Done."
echo "[+] Alive subdomains: $(wc -l < "$ALIVE_HOSTS") in activesubs.txt (temp)"
echo "[+] Total unique real IPs: $(wc -l < "$IPS_OUT")"

cp "$ALIVE_HOSTS" "$ACTIVE_OUT"

# Append section to fullreport.txt for later review
{
    echo ""
    echo "========================================================================="
    echo " [dsiprecon] IP RESOLUTION $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================================================="
    echo "[*] Alive subdomains   : $(wc -l < "$ACTIVE_OUT" | tr -d ' ')"
    echo "[*] Unique IPs         : $(wc -l < "$IPS_OUT" | tr -d ' ')"
    echo "[*] origin_ips.txt :"
    cat "$ORIGIN_OUT" 2>/dev/null
    echo ""
} >> fullreport.txt 2>/dev/null

rm -rf "$TMP"

exit 0
