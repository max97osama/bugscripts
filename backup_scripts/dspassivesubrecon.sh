#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <domain|domains.txt> [subdomains.txt]"
    exit 1
fi

INPUT="$1"
SUBDOMAINS_FILE="${2:-subdomains.txt}"

touch "$SUBDOMAINS_FILE"

DOMAINS_LIST="/tmp/pd_domains_$$.txt"
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

echo "[*] Total domains to process: $(wc -l < "$DOMAINS_LIST")"

SUBS_OUT="subs.txt"
CLEANED_OUT="cleanedsubs.txt"
IPS_OUT="ips.txt"
IPSV6_OUT="ipsv6.txt"
VALID_OUT="validsubs.txt"

touch "$SUBS_OUT" "$CLEANED_OUT" "$IPS_OUT" "$IPSV6_OUT" "$VALID_OUT"

AMASS_RAW="/tmp/amass_raw_$$.txt"
AMASS_IPS_RAW="/tmp/amass_ips_raw_$$.txt"
SUBFINDER_RAW="/tmp/subfinder_raw_$$.txt"
SUBLIST3R_RAW="/tmp/sublist3r_raw_$$.txt"
HAKTRAILS_RAW="/tmp/haktrails_raw_$$.txt"
ALL_SUBS_RAW="/tmp/all_subs_raw_$$.txt"
ALL_IPS_RAW="/tmp/all_ips_raw_$$.txt"
DNSX_RAW="/tmp/dnsx_raw_$$.txt"
HTTPX_RAW="/tmp/httpx_raw_$$.txt"

> "$AMASS_RAW"
> "$AMASS_IPS_RAW"
> "$SUBFINDER_RAW"
> "$SUBLIST3R_RAW"
> "$HAKTRAILS_RAW"
> "$ALL_SUBS_RAW"
> "$ALL_IPS_RAW"
> "$DNSX_RAW"
> "$HTTPX_RAW"

IP_REGEX="([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
IPV6_REGEX="([0-9a-fA-F]{0,4}:[0-9a-fA-F:]{2,39})"

while IFS= read -r DOMAIN; do
    echo "[*] Starting passive recon for: $DOMAIN"

    echo "[*] Running amass passive (hostnames)..."
    amass enum -passive -d "$DOMAIN" 2>/dev/null >> "$AMASS_RAW"

    sleep 3

    echo "[*] Running amass passive (with IPs)..."
    amass enum -passive -d "$DOMAIN" -ip 2>/dev/null >> "$AMASS_IPS_RAW"

    sleep 5

    echo "[*] Running subfinder..."
    subfinder -d "$DOMAIN" \
        -t 1 \
        -timeout 30 \
        -silent \
        2>/dev/null >> "$SUBFINDER_RAW"

    sleep 5

    echo "[*] Running sublist3r..."
    sublist3r -d "$DOMAIN" 2>/dev/null >> "$SUBLIST3R_RAW"

    sleep 5

    echo "[*] Running haktrails subdomains..."
    echo "$DOMAIN" | haktrails subdomains 2>/dev/null >> "$HAKTRAILS_RAW"

    sleep 5

done < "$DOMAINS_LIST"

echo "[*] Amass hostnames found: $(wc -l < "$AMASS_RAW")"
echo "[*] Subfinder hostnames found: $(wc -l < "$SUBFINDER_RAW")"
echo "[*] Sublist3r hostnames found: $(wc -l < "$SUBLIST3R_RAW")"
echo "[*] Haktrails hostnames found: $(wc -l < "$HAKTRAILS_RAW")"

grep -oE "$IP_REGEX" "$AMASS_IPS_RAW" >> "$ALL_IPS_RAW"

echo "[*] Extracting hostnames from all raw outputs..."

python3 - <<PYEOF
import re

domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$')

domains = set()
with open('$DOMAINS_LIST', 'r') as f:
    for line in f:
        d = line.strip()
        if d:
            domains.add(d)

def belongs_to_target(host):
    for d in domains:
        if host == d or host.endswith('.' + d):
            return True
    return False

found = set()
for raw_file in ['$AMASS_RAW', '$AMASS_IPS_RAW', '$SUBFINDER_RAW', '$SUBLIST3R_RAW', '$HAKTRAILS_RAW']:
    try:
        with open(raw_file, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                tokens = re.split(r'[\s,]+', line)
                for token in tokens:
                    token = token.strip().rstrip('.')
                    if not token:
                        continue
                    if domain_pattern.match(token) and belongs_to_target(token):
                        found.add(token.lower())
    except FileNotFoundError:
        continue

with open('$ALL_SUBS_RAW', 'w') as f:
    for h in sorted(found):
        f.write(h + '\n')

print(f'[+] Total unique hostnames extracted: {len(found)}')
PYEOF

cat "$SUBDOMAINS_FILE" >> "$ALL_SUBS_RAW"
sort -u "$ALL_SUBS_RAW" -o "$ALL_SUBS_RAW"

echo "[*] Total unique candidates before resolution: $(wc -l < "$ALL_SUBS_RAW")"

echo "[*] Resolving all candidates with dnsx..."
dnsx -l "$ALL_SUBS_RAW" \
    -t 1 \
    -rl 5 \
    -a \
    -aaaa \
    -resp \
    -silent \
    2>/dev/null > "$DNSX_RAW"

echo "[*] dnsx resolved lines: $(wc -l < "$DNSX_RAW")"

echo "[*] Checking alive status with httpx..."
awk '{print $1}' "$DNSX_RAW" | sort -u > /tmp/pd_resolved_hosts_$$.txt

httpx -l /tmp/pd_resolved_hosts_$$.txt \
    -threads 1 \
    -rate-limit 5 \
    -timeout 10 \
    -status-code \
    -silent \
    2>/dev/null > "$HTTPX_RAW"

echo "[*] httpx alive results: $(wc -l < "$HTTPX_RAW")"

echo "[*] Building final output files..."

python3 - <<PYEOF2
import re

ipv4_pat = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

httpx_map = {}
with open('$HTTPX_RAW', 'r', errors='ignore') as f:
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
all_v4 = set()
all_v6 = set()

with open('$DNSX_RAW', 'r', errors='ignore') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        sub = parts[0]
        bracket_vals = re.findall(r'\[([^\]]+)\]', line)
        ips_v4 = []
        ips_v6 = []
        for val in bracket_vals:
            if ipv4_pat.match(val):
                ips_v4.append(val)
                all_v4.add(val)
            elif ':' in val:
                ips_v6.append(val)
                all_v6.add(val)
        ip = ips_v4[0] if ips_v4 else (ips_v6[0] if ips_v6 else '0.0.0.0')
        dnsx_map[sub] = ip

with open('$ALL_SUBS_RAW', 'r') as f:
    subs = [line.strip() for line in f if line.strip()]

subs_out = open('$SUBS_OUT', 'w')
cleaned_out = open('$CLEANED_OUT', 'w')
valid_out = open('$VALID_OUT', 'w')

valid_ips_v4 = set()
valid_ips_v6 = set()

for sub in subs:
    code = httpx_map.get(sub, 'N/A')
    ip = dnsx_map.get(sub, '0.0.0.0')
    status_text = 'OK' if code == '200' else code
    subs_out.write(f'{sub} {code} {status_text} {ip} {sub}\n')
    cleaned_out.write(f'{sub}\n')
    if code == '200':
        valid_out.write(f'{sub}\n')
        if ip != '0.0.0.0':
            if ':' in ip:
                valid_ips_v6.add(ip)
            else:
                valid_ips_v4.add(ip)

subs_out.close()
cleaned_out.close()
valid_out.close()

existing_v4 = set()
try:
    with open('$IPS_OUT', 'r') as f:
        for line in f:
            ip = line.strip()
            if ip:
                existing_v4.add(ip)
except FileNotFoundError:
    pass

existing_v6 = set()
try:
    with open('$IPSV6_OUT', 'r') as f:
        for line in f:
            ip = line.strip()
            if ip:
                existing_v6.add(ip)
except FileNotFoundError:
    pass

all_v4 |= existing_v4
all_v6 |= existing_v6

with open('$ALL_IPS_RAW', 'r') as f:
    for line in f:
        ip = line.strip()
        if ipv4_pat.match(ip):
            all_v4.add(ip)

with open('$IPS_OUT', 'w') as f:
    for ip in sorted(all_v4):
        f.write(ip + '\n')

with open('$IPSV6_OUT', 'w') as f:
    for ip in sorted(all_v6):
        f.write(ip + '\n')

print(f'[+] subs.txt total entries: {len(subs)}')
print(f'[+] validsubs.txt (200 OK): {sum(1 for s in subs if httpx_map.get(s,"") == "200")}')
print(f'[+] ips.txt total unique IPv4: {len(all_v4)}')
print(f'[+] ipsv6.txt total unique IPv6: {len(all_v6)}')
PYEOF2

NEW=$(comm -23 <(sort "$CLEANED_OUT") <(sort "$SUBDOMAINS_FILE"))
NEW_COUNT=$(echo "$NEW" | grep -c ".")
echo "$NEW" >> "$SUBDOMAINS_FILE"
sort -u "$SUBDOMAINS_FILE" -o "$SUBDOMAINS_FILE"

echo "[+] $NEW_COUNT new subdomains added to $SUBDOMAINS_FILE"
echo "[+] Output files: $SUBS_OUT | $CLEANED_OUT | $IPS_OUT | $IPSV6_OUT | $VALID_OUT"

rm -f "$AMASS_RAW" "$AMASS_IPS_RAW" "$SUBFINDER_RAW" "$SUBLIST3R_RAW" "$HAKTRAILS_RAW" \
    "$ALL_SUBS_RAW" "$ALL_IPS_RAW" "$DNSX_RAW" "$HTTPX_RAW" \
    "$DOMAINS_LIST" /tmp/pd_resolved_hosts_$$.txt
