#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <target-ip-or-domain>"
    exit 1
fi

TARGET="$1"
REPORT="nmapreport.txt"
RAW_OUT="/tmp/nmap_raw_$$.txt"

> "$REPORT"

echo "[*] Starting full nmap vulnerability scan on: $TARGET"
echo "[*] This will take a while..."

nmap -sV -sC \
    --script vuln \
    -p- \
    -T2 \
    --min-rate 100 \
    --max-rate 300 \
    --max-retries 2 \
    --host-timeout 60m \
    -oN "$RAW_OUT" \
    "$TARGET" 2>/dev/null

if [ ! -f "$RAW_OUT" ]; then
    echo "[-] Nmap failed to run or produced no output."
    exit 1
fi

echo "================================================================" >> "$REPORT"
echo "NMAP VULNERABILITY REPORT FOR: $TARGET" >> "$REPORT"
echo "Date: $(date)" >> "$REPORT"
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

echo "[+] Done."
echo "[+] Vulnerability report saved to: $REPORT"
echo "[+] Total lines in report: $(wc -l < "$REPORT")"

rm -f "$RAW_OUT"