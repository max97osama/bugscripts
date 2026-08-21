#!/bin/bash

usage() {
    echo "Usage: $0 -d <domain> -l <subdomain_list> -o <output_file>"
    exit 1
}

while getopts ":d:l:o:" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        l) SUBLIST="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        *) usage ;;
    esac
done

if [[ -z "$DOMAIN" || -z "$SUBLIST" || -z "$OUTPUT" ]]; then
    usage
fi

if ! command -v nuclei >/dev/null 2>&1; then
    echo "[-] nuclei not found on PATH. Install it before running hunter.sh"
    exit 1
fi

nuclei -update-templates -silent

trap 'echo "Interrupted, exiting."; exit 130' INT

nuclei -list "$SUBLIST" \
    -tags exposure,vulnerability,default-login,cve,misconfig,takeover,tech \
    -severity critical,high,medium,low \
    -c 2 \
    -bs 2 \
    -rl 15 \
    -timeout 10 \
    -stats \
    -o "$OUTPUT" \
    -etags headless \
    -mhe 1 \
    -ni \
    2>> nuclei_errors.log

if [ $? -eq 0 ]; then
    echo "Done: $OUTPUT"
else
    echo "Error: Check nuclei_errors.log"
fi

echo ""
echo "[*] Subdomain takeover pass on $SUBLIST..."
TAKEOVER_OUT="${OUTPUT%.txt}_takeover.txt"
> "$TAKEOVER_OUT"

if command -v subjack >/dev/null 2>&1; then
    subjack -w "$SUBLIST" -t 3 -timeout 20 -o "$TAKEOVER_OUT" -ssl \
        -c /root/go/src/github.com/haccer/subjack/fingerprints.json 2>/dev/null \
        || subjack -w "$SUBLIST" -t 3 -timeout 20 -o "$TAKEOVER_OUT" -ssl 2>/dev/null
fi

echo "[*] CNAME dangling-record analysis..."
while IFS= read -r t; do
    t=$(echo "$t" | tr -d '[:space:]')
    [ -z "$t" ] && continue
    CNAME=$(dig +short CNAME "$t" 2>/dev/null | head -1)
    if echo "$CNAME" | grep -qiE "(github\.io|herokuapp|aws\.[a-z-]+\.com|s3[-.]|azurewebsites|cloudfront|pantheon|netlify|vercel|surge\.sh|readme\.io|ghost\.io|mashery|status\.io|zendesk|wordpress\.com)"; then
        echo "[CANDIDATE] $t -> $CNAME" | tee -a "$TAKEOVER_OUT"
    fi
    sleep 1
done < "$SUBLIST"

echo "Takeover results: $TAKEOVER_OUT"

{
    echo ""
    echo "========================================================================="
    echo " [dshunter] NUCLEI + TAKEOVER SCAN $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================================================="
    echo "[*] Nuclei findings :"
    cat "$OUTPUT" 2>/dev/null
    echo ""
    echo "[*] Takeover candidates :"
    cat "$TAKEOVER_OUT" 2>/dev/null
    echo ""
} >> fullreport.txt 2>/dev/null
