#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <target-ip-or-domain>"
    exit 1
fi

TARGET="$1"
REPORT="nmapreport.txt"
NET_REPORT="network.txt"
RAW_OUT="/tmp/nmap_raw_$$.txt"
NAABU_OUT="/tmp/naabu_$$.json"

> "$REPORT"

NAABU_RATE=200
NAABU_THREADS=25

if command -v naabu >/dev/null 2>&1; then
    echo "[*] Running naabu fast pre-scan on all 65535 ports for: $TARGET"
    timeout 600 naabu -host "$TARGET" -p - \
        -rate "$NAABU_RATE" \
        -c "$NAABU_THREADS" \
        -silent -json \
        -o "$NAABU_OUT" 2>/dev/null

    PORTS=$(python3 -c "
import json
ports = set()
try:
    with open('$NAABU_OUT') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                p = data.get('port')
                if p:
                    ports.add(int(p))
            except Exception:
                continue
except FileNotFoundError:
    pass
print(','.join(str(p) for p in sorted(ports)))
")

    if [ -z "$PORTS" ]; then
        echo "[*] naabu found no open ports on $TARGET, skipping nmap entirely."
        echo "================================================================" >> "$REPORT"
        echo "NMAP VULNERABILITY REPORT FOR: $TARGET" >> "$REPORT"
        echo "Date: $(date)" >> "$REPORT"
        echo "================================================================" >> "$REPORT"
        echo "" >> "$REPORT"
        echo "[*] No open ports found by naabu pre-scan, nmap skipped." >> "$REPORT"
        rm -f "$NAABU_OUT"
        exit 0
    fi

    echo "[+] naabu found open ports: $PORTS"
    rm -f "$NAABU_OUT"

    echo "[*] Running targeted nmap vuln scan on confirmed open ports only..."
    timeout 1200 nmap -sV -sC \
        --script vuln \
        -p "$PORTS" \
        -T3 \
        -n \
        --max-retries 2 \
        --host-timeout 15m \
        --script-timeout 90s \
        -oN "$RAW_OUT" \
        "$TARGET" 2>/dev/null
else
    echo "[-] naabu not found, falling back to nmap's own full-range discovery (slower)."
    echo "[*] Starting full nmap vulnerability scan on: $TARGET"
    echo "[*] This will take a while..."

    timeout 2700 nmap -sV -sC \
        --script vuln \
        -p- \
        -T3 \
        -n \
        --min-rate 100 \
        --max-rate 300 \
        --max-retries 2 \
        --host-timeout 25m \
        --script-timeout 90s \
        --stats-every 60s \
        -oN "$RAW_OUT" \
        "$TARGET" 2>/dev/null
fi

NMAP_EXIT=$?

if [ ! -f "$RAW_OUT" ]; then
    echo "[-] Nmap failed to run or produced no output."
    exit 1
fi

if [ "$NMAP_EXIT" -eq 124 ]; then
    echo "[!] Scan hit its hard time limit and was terminated early. Results may be partial."
fi

echo "================================================================" >> "$REPORT"
echo "NMAP VULNERABILITY REPORT FOR: $TARGET" >> "$REPORT"
echo "Date: $(date)" >> "$REPORT"
if [ "$NMAP_EXIT" -eq 124 ]; then
    echo "NOTE: Scan was terminated at the hard time limit. Results may be partial." >> "$REPORT"
fi
echo "================================================================" >> "$REPORT"
echo "" >> "$REPORT"

python3 - <<PYEOF "$RAW_OUT" "$REPORT"
import sys, re

raw_file = sys.argv[1]
report_file = sys.argv[2]

with open(raw_file, 'r') as f:
    content = f.read()

vuln_keywords = [
    'VULNERABLE','CVE-','State: VULNERABLE','State: LIKELY VULNERABLE',
    'exploitable','Exploit','exploit','Risk factor','HIGH','CRITICAL',
    'disclosure','injection','overflow','bypass','traversal','RCE',
    'remote code','XSS','SQL','SSRF','LFI','RFI','open redirect',
    'misconfiguration','weak','brute','default credentials','anonymous',
    'cleartext','unencrypted','backdoor',
]

blocks = re.split(r'\n(?=\d+/)', content)
found_any = False

with open(report_file, 'a') as out:
    for block in blocks:
        block_lower = block.lower()
        matched = [kw for kw in vuln_keywords if kw.lower() in block_lower]
        if matched:
            found_any = True
            out.write(block.strip() + '\n')
            out.write(f'[!] Triggered keywords: {", ".join(set(matched))}\n')
            out.write('----------------------------------------------------------------\n')

    script_sections = re.findall(r'(\|\s*\w[\w\-]+:.*?)(?=\n\d+/|\Z)', content, re.DOTALL)
    for section in script_sections:
        matched = [kw for kw in vuln_keywords if kw.lower() in section.lower()]
        if matched:
            found_any = True
            out.write(section.strip() + '\n')
            out.write(f'[!] Triggered keywords: {", ".join(set(matched))}\n')
            out.write('----------------------------------------------------------------\n')

    if not found_any:
        out.write('[*] No vulnerabilities detected by nmap scripts on this target.\n')
    else:
        out.write('\n================================================================\n')
        out.write('[+] Scan complete. Review findings above.\n')
        out.write('================================================================\n')
PYEOF

python3 - <<PYEOF "$RAW_OUT" "$NET_REPORT" "$TARGET"
import sys, re
from datetime import datetime

raw_file = sys.argv[1]
net_file = sys.argv[2]
target = sys.argv[3]

with open(raw_file, 'r', errors='ignore') as f:
    content = f.read()

RISKY = {
    'ftp': 'Anonymous FTP access or credential sniffing risk',
    'telnet': 'Cleartext credentials, should not be exposed',
    'snmp': 'Information disclosure of OS/hardware/network details',
    'smb': 'Check for EternalBlue / SMB relay exposure',
    'rdp': 'Check for BlueKeep and brute-force exposure',
    'redis': 'Often unauthenticated, can lead to RCE',
    'mongodb': 'Often unauthenticated, full DB read/write risk',
    'elasticsearch': 'Often unauthenticated, full data dump risk',
    'memcached': 'Unauthenticated access, DDoS amplification risk',
    'docker': 'Unauthenticated Docker API, full container takeover risk',
    'vnc': 'Check for no-auth remote desktop access',
    'mysql': 'Check for weak/default credentials',
    'postgresql': 'Check for weak/default credentials',
    'http-proxy': 'Open proxy misuse risk',
}

open_ports = []
port_pattern = re.compile(r'^(\d+)/(tcp|udp)\s+(open)\s+(\S+)\s*(.*)$', re.MULTILINE)
for m in port_pattern.finditer(content):
    port, proto, state, service, version = m.groups()
    open_ports.append((port, proto, service.strip(), version.strip()))

confirmed_vulns = []
blocks = re.split(r'\n(?=\| |\|_)', content)
current_script = None
for block in blocks:
    header_match = re.match(r'\|_?\s*([\w\-\.]+):', block)
    if header_match:
        current_script = header_match.group(1)
    if 'State: VULNERABLE' in block:
        prior_text = block.split('State: VULNERABLE')[0]
        last_line = prior_text.strip().split('\n')[-1] if prior_text.strip() else ''
        if 'LIKELY' in last_line:
            continue
        cve_matches = re.findall(r'CVE-\d{4}-\d+', block)
        title_match = re.search(r'\|\s+(.+)\n\s*\|\s+VULNERABLE', block)
        title = title_match.group(1).strip() if title_match else (current_script or 'Unknown')
        cve_str = ', '.join(sorted(set(cve_matches))) if cve_matches else 'No CVE listed'
        confirmed_vulns.append(f"{title} -- {cve_str}")

with open(net_file, 'a') as out:
    out.write('================================================================\n')
    out.write(f'NETWORK SUMMARY FOR: {target}\n')
    out.write(f'Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
    out.write('================================================================\n\n')

    out.write('OPEN PORTS\n')
    out.write('----------\n')
    if open_ports:
        for port, proto, service, version in open_ports:
            line = f"{port}/{proto}  {service}"
            if version:
                line += f"  {version}"
            out.write(line + '\n')
    else:
        out.write('No open ports found.\n')
    out.write('\n')

    out.write('POTENTIAL THREATS\n')
    out.write('-----------------\n')
    threat_found = False
    for port, proto, service, version in open_ports:
        service_lower = service.lower()
        for keyword, note in RISKY.items():
            if keyword in service_lower:
                out.write(f"{port}/{proto} ({service}): {note}\n")
                threat_found = True
    if not threat_found:
        out.write('No high-risk services identified by service name.\n')
    out.write('\n')

    out.write('CONFIRMED VULNERABILITIES\n')
    out.write('-------------------------\n')
    if confirmed_vulns:
        for v in confirmed_vulns:
            out.write(f"{v}\n")
    else:
        out.write('No confirmed (State: VULNERABLE) findings from nmap vuln scripts.\n')
    out.write('\n')
PYEOF

echo "[+] Done."
echo "[+] Full vulnerability report saved to: $REPORT"
echo "[+] Short network report saved to: $NET_REPORT"
echo "[+] Total lines in full report: $(wc -l < "$REPORT")"

{
    echo ""
    echo "========================================================================="
    echo " [dsnmapscan] NMAP SCAN REPORT FOR $TARGET $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================================================="
    cat "$NET_REPORT" 2>/dev/null
    echo ""
} >> fullreport.txt 2>/dev/null

rm -f "$RAW_OUT"
