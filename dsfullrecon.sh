#!/bin/bash

usage() {
    echo "Usage: $0 [--no-subs] <domain|domains.txt> [subdomains_wordlist.txt] [kite_wordlist] [dir_wordlist.txt]"
    echo ""
    echo "    <domain>             a single target domain (e.g. example.com)"
    echo "    <domains.txt>        a file containing a list of domains (one per line)"
    echo "    --no-subs            skip subdomain discovery and run against the given target only"
    echo ""
    echo "    example wordlists :"
    echo "      /root/wordlist/shorts/subdomains.txt /root/wordlist/large.kite /root/wordlist/shorts/dir.txt"
}

NO_SUBS=0
ARGS=()
for arg in "$@"; do
    if [ "$arg" = "--no-subs" ]; then
        NO_SUBS=1
    else
        ARGS+=("$arg")
    fi
done

if [ "${#ARGS[@]}" -lt 1 ]; then
    usage
    exit 1
fi

TARGET="${ARGS[0]}"

if [ -z "$TARGET" ]; then
    usage
    exit 1
fi

if [ -f "$TARGET" ]; then
    DOMAIN="$(cd "$(dirname "$TARGET")" && pwd)/$(basename "$TARGET")"
    TARGET_IS_FILE=1
    BASE_NAME="$(basename "$TARGET" | sed 's/\.txt$//')"
elif echo "$TARGET" | grep -qE "^[a-zA-Z0-9][a-zA-Z0-9.-]*$"; then
    DOMAIN="$TARGET"
    TARGET_IS_FILE=0
    BASE_NAME="$TARGET"
else
    echo "[-] Invalid target: '$TARGET'. Provide a domain name or a list of domains in a .txt file." >&2
    echo ""
    usage >&2
    exit 1
fi

SUBS_WORDLIST="${ARGS[1]:-}"
KITE_WORDLIST="${ARGS[2]:-}"
DIR_WORDLIST="${ARGS[3]:-}"

# Run dir = just the bare domain label without TLD and without "_recon"
# (e.g. watson.ch -> watson). Paginate with _1, _2 if it already exists.
RUN_DIR="$(echo "$BASE_NAME" | sed -E 's/^www\.//; s/\.[a-z]{2,}$//')"
if [ -z "$RUN_DIR" ]; then
    RUN_DIR="$BASE_NAME"
fi
if [ -d "$RUN_DIR" ]; then
    NUM=1
    while [ -d "${RUN_DIR}_${NUM}" ]; do
        NUM=$((NUM+1))
    done
    RUN_DIR="${RUN_DIR}_${NUM}"
fi
mkdir -p "$RUN_DIR"
cd "$RUN_DIR"

SUBDOMAINS_FILE="subdomains.txt"
IPS_FILE="ips.txt"
URLS_FILE="urls.txt"
JS_FILE="js.txt"
PARAMS_FILE="parameters.txt"
STEP_LOG="recon_steps.txt"

touch "$SUBDOMAINS_FILE" "$IPS_FILE" "$URLS_FILE" "$JS_FILE"
touch "$STEP_LOG"

log() {
    echo ""
    echo "========================================================"
    echo "  $1"
    echo "========================================================"
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

has_file() {
    [ -f "$1" ] && [ -s "$1" ]
}

step() {
    local name="$1"
    local desc="$2"
    {
        echo "========================================================"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] STEP: $name - $desc"
        echo "========================================================"
    } | tee -a "$STEP_LOG"
    log "$name - $desc"
    echo "$name $desc" >> "$STEP_LOG"
}

run() {
    local cmd_name="$1"
    local real="${cmd_name#ds}"
    if has_cmd "$cmd_name"; then
        echo "[*] Running $cmd_name ..." | tee -a "$STEP_LOG"
        shift
        "$cmd_name" "$@"
        local rc=$?
        echo "[*] $cmd_name finished (exit $rc)." | tee -a "$STEP_LOG"
        sleep 5
        return $rc
    else
        echo "[-] $cmd_name not found on PATH. Skipping ${1:-}." | tee -a "$STEP_LOG"
        return 0
    fi
}

if [ "$NO_SUBS" -eq 1 ]; then
    step "NO-SUBS" "Running against target only"
    if [ "$TARGET_IS_FILE" -eq 1 ]; then
        echo "Running against domain list: $DOMAIN"
        cat "$DOMAIN" >> "$SUBDOMAINS_FILE"
    else
        echo "Running against single domain only: $DOMAIN"
        echo "$DOMAIN" >> "$SUBDOMAINS_FILE"
    fi
    sort -u "$SUBDOMAINS_FILE" -o "$SUBDOMAINS_FILE"
else
    step "STEP 1" "Passive subdomain recon (amass/subfinder/sublist3r/crt.sh/OTX/RapidDNS/Shodan)"
    run dspassivesubrecon "$DOMAIN" "$SUBDOMAINS_FILE"

    step "STEP 2" "Active subdomain bruteforce"
    if [ -f "$SUBS_WORDLIST" ] && [ -s "$SUBS_WORDLIST" ]; then
        run dsbrutesubrecon "$DOMAIN" "$SUBS_WORDLIST" "$SUBDOMAINS_FILE"
    else
        echo "[-] Brute skipped: provide subdomains wordlist arg. (example: /root/wordlist/shorts/subdomains.txt)" | tee -a "$STEP_LOG"
    fi
fi

step "STEP 3" "Resolve real IPs + origin IPs behind CDN (dsIPRecon)"
run dsiprecon "$SUBDOMAINS_FILE"
if has_file "activesubs.txt"; then
    cp activesubs.txt "$SUBDOMAINS_FILE"
    echo "[+] subdomains.txt updated with alive subdomains only." | tee -a "$STEP_LOG"
fi

step "STEP 4" "Tech stack + WAF + security headers fingerprinting (dsTechRecon)"
run dstechrecon "$SUBDOMAINS_FILE"

step "STEP 5" "Nmap vulnerability scan on each real IP (dsNmapScan)"
if has_file "$IPS_FILE"; then
    while IFS= read -r ip; do
        ip=$(echo "$ip" | tr -d '[:space:]')
        [ -z "$ip" ] && continue
        echo "[*] Nmap scanning: $ip" | tee -a "$STEP_LOG"
        run dsnmapscan "$ip"
        sleep 10
    done < "$IPS_FILE"
else
    echo "[-] Nmap skipped: no ips.txt." | tee -a "$STEP_LOG"
fi

step "STEP 6" "Mass nuclei scan + subdomain takeover (dsHunter)"
run dshunter -d "$DOMAIN" -l "$SUBDOMAINS_FILE" -o "hunter_out.txt"

step "STEP 7" "URL gathering (archives + crawlers + dir-fuzz) (dsURLRecon)"
if [ -f "$DIR_WORDLIST" ] && [ -s "$DIR_WORDLIST" ]; then
    run dsurlrecon "$DOMAIN" -l "$SUBDOMAINS_FILE" "$DIR_WORDLIST"
else
    run dsurlrecon "$DOMAIN" -l "$SUBDOMAINS_FILE"
fi

step "STEP 8" "JS endpoints + secrets extraction (dsJSRecon)"
run dsjsrecon "js.txt"

step "STEP 9" "API recon / params / open-redirect / header-injection / JWT (dsAPIRecon)"
if [ -f "$KITE_WORDLIST" ] && [ -s "$KITE_WORDLIST" ]; then
    run dsapirecon "$DOMAIN" "$SUBDOMAINS_FILE" "$KITE_WORDLIST"
else
    echo "[-] API/header stage: kite wordlist not provided (example: /root/wordlist/large.kite). Running without kiterunner."
    run dsapirecon "$DOMAIN" "$SUBDOMAINS_FILE" ""
fi
if has_file "vulnerable_urls.txt"; then
    cat vulnerable_urls.txt >> "$URLS_FILE"
    sort -u "$URLS_FILE" -o "$URLS_FILE"
fi

step "STEP 10" "Filter + classify + secret-scan URLs (dsURLFilter)"
run dsurlfilter "$URLS_FILE" "$DOMAIN"

step "STEP 11" "Misc asset bug checks: cloud / git-exposure / GraphQL (dsCloudPermissions)"
run dscloudpermissions "$SUBDOMAINS_FILE"

step "STEP 12" "Injection scans: XSS + SQLi + command-injection + smuggling (dsXSSRecon)"
if has_file "$PARAMS_FILE"; then
    run dsxssrecon "$PARAMS_FILE" "" "$SUBDOMAINS_FILE"
else
    echo "[-] Injection skipped: no parameters.txt." | tee -a "$STEP_LOG"
fi

step "DONE" "Full recon complete"
echo ""

echo "[*] Generating fullreport.txt (aggregated analysis for future review)..."
FULLREPORT="fullreport.txt"
: > "$FULLREPORT"

{
    echo "========================================================================="
    echo "  FULL RECON REPORT  -  $DOMAIN"
    echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Run dir   : $(pwd)"
    echo "========================================================================="
    echo ""
    echo "NOTE: This is a living/aggregated report. Individual stage scripts also"
    echo "append their own sections to fullreport.txt as they finish."
    echo ""
} >> "$FULLREPORT"

# 1) Scope / inventory
{
    echo "========================================================================="
    echo " 1. SCOPE & INVENTORY"
    echo "========================================================================="
    echo "[*] Target: $DOMAIN"
    if [ -f "$SUBDOMAINS_FILE" ]; then
        echo "[*] Total subdomains collected : $(wc -l < "$SUBDOMAINS_FILE" | tr -d ' ')"
        echo ""
        echo "--- subdomains.txt ---"
        cat "$SUBDOMAINS_FILE"
    fi
    if [ -s "activesubs.txt" ]; then
        echo ""
        echo "--- activesubs.txt (alive) : $(wc -l < activesubs.txt | tr -d ' ') ---"
        cat activesubs.txt
    fi
    echo ""
} >> "$FULLREPORT"

# 2) IPs / origin IPs
{
    echo "========================================================================="
    echo " 2. IP ADDRESSES"
    echo "========================================================================="
    if [ -s "$IPS_FILE" ]; then
        echo "[*] Resolved/all IPs (ips.txt) : $(wc -l < "$IPS_FILE" | tr -d ' ')"
        cat "$IPS_FILE"
    fi
    if [ -s "origin_ips.txt" ]; then
        echo ""
        echo "[*] Likely ORIGIN IPs behind CDN (origin_ips.txt) : $(wc -l < origin_ips.txt | tr -d ' ')"
        cat origin_ips.txt
    fi
    echo ""
} >> "$FULLREPORT"

# 3) URLs
{
    echo "========================================================================="
    echo " 3. URLS"
    echo "========================================================================="
    if [ -s "$URLS_FILE" ]; then
        echo "[*] Total unique URLs (urls.txt) : $(wc -l < "$URLS_FILE" | tr -d ' ')"
        echo ""
        echo "--- urls.txt ---"
        cat "$URLS_FILE"
    fi
    echo ""
} >> "$FULLREPORT"

# 4) Attack surface (juicy/interesting URLs)
{
    echo "========================================================================="
    echo " 4. ATTACK SURFACE (params / endpoints / js)"
    echo "========================================================================="
    if [ -s "$PARAMS_FILE" ]; then
        echo "[*] Parameterized URLs (parameters.txt) : $(wc -l < "$PARAMS_FILE" | tr -d ' ')"
        echo "--- parameters.txt ---"
        cat "$PARAMS_FILE"
    fi
    echo ""
    if [ -s "endpoints.txt" ]; then
        echo "[*] JS/API endpoints (endpoints.txt) : $(wc -l < endpoints.txt | tr -d ' ')"
        echo "--- endpoints.txt ---"
        cat endpoints.txt
    fi
    if [ -s "js.txt" ]; then
        echo ""
        echo "[*] JS files (js.txt) : $(wc -l < js.txt | tr -d ' ')"
        cat js.txt
    fi
    if [ -s "jsecrets.txt" ]; then
        echo ""
        echo "[*] Secrets found in JS (jsecrets.txt) : $(wc -l < jsecrets.txt | tr -d ' ')"
        cat jsecrets.txt
    fi
    echo ""
} >> "$FULLREPORT"

# 5) Tech / services
{
    echo "========================================================================="
    echo " 5. TECHNOLOGY & SERVICES"
    echo "========================================================================="
    if [ -s "techstack.txt" ]; then
        echo "[*] Tech stack summary (techstack.txt):"
        cat techstack.txt
    fi
    if [ -s "tech.txt" ]; then
        echo ""
        echo "[*] Full tech fingerprint (tech.txt):"
        cat tech.txt
    fi
    echo ""
} >> "$FULLREPORT"

# 6) Vulnerabilities
{
    echo "========================================================================="
    echo " 6. VULNERABILITIES / FINDINGS"
    echo "========================================================================="
    for rep in nmapreport.txt network.txt hunter_out.txt hunter_out_takeover.txt \
               report.txt vulnerable_urls.txt headerinject.txt xssreport.txt sqlreport.txt cmdireport.txt \
               smugglerreport.txt cloudreport.txt gitrecon.txt graphql_report.txt \
               jwtreport.txt; do
        if [ -s "$rep" ]; then
            echo "--- $rep : $(wc -l < "$rep" | tr -d ' ') lines ---"
            cat "$rep"
            echo ""
        fi
    done
    echo ""
} >> "$FULLREPORT"

# 7) Request/response details from API stage (if params to test)
# 8) Classified vuln URLs
{
    echo "========================================================================="
    echo " 7. CLASSIFIED URLS (gf) / NEXT-STEP GUIDANCE"
    echo "========================================================================="
    for p in sqli xxe ssti redirect rce lfi idor ssrf xss interestingparams; do
        if [ -s "$p.txt" ]; then
            echo "--- ${p}.txt : $(wc -l < "$p.txt" | tr -d ' ') URLs ---"
            cat "$p.txt"
            echo ""
        fi
    done
    echo
    echo "========================================================================="
    echo " 8. EXECUTION LOG"
    echo "========================================================================="
    if [ -s "$STEP_LOG" ]; then
        cat "$STEP_LOG"
    fi
} >> "$FULLREPORT"

echo "[+] Full report saved to: $FULLREPORT ($(wc -l < "$FULLREPORT" | tr -d ' ') lines)"
echo ""

echo "[*] Cleaning up redundant/intermediate files (data already consolidated in fullreport.txt)..."
# Remove per-stage duplicates / subsets / intermediate artifacts.
# (Still produced during the run for downstream steps; only removed at the end.)
# NOTE: activesubs.txt, vulnerable_urls.txt, recon_steps.txt are KEPT on purpose.
rm -f \
    origin_ips.txt \
    subs.txt \
    cleanedsubs.txt \
    validsubs.txt \
    ipsv6.txt \
    curls.txt \
    findurls.txt \
    new_urls.txt \
    burl.txt \
    alljs.txt \
    Findings.txt \
    endpoints.txt \
    jsecrets.txt \
    2>/dev/null

# Remove empty result files (issue: many 0-byte files were left before).
echo "[*] Removing empty result files..."
find . -maxdepth 1 -type f -size 0c -delete

# Keep a concise per-asset inventory only for the surviving core files.
echo ""
echo "[+] Final consolidated outputs (run dir: $(pwd)):"
echo "    ASSETS:"
for f in subdomains.txt activesubs.txt ips.txt urls.txt parameters.txt js.txt cleaned.txt; do
    [ -f "$f" ] && echo "      $f — $(wc -l < "$f" | tr -d ' ') lines"
done
echo "    SCAN RESULTS:"
for f in fullreport.txt tech.txt techstack.txt nmapreport.txt network.txt \
         hunter_out.txt hunter_out_takeover.txt report.txt vulnerable_urls.txt \
         headerinject.txt xssreport.txt sqlreport.txt cmdireport.txt smugglerreport.txt \
         cloudreport.txt gitrecon.txt graphql_report.txt jwtreport.txt; do
    [ -f "$f" ] && echo "      $f — $(wc -l < "$f" | tr -d ' ') lines"
done
echo "    CLASSIFIED URLS:"
for f in sqli.txt xxe.txt ssti.txt redirect.txt rce.txt lfi.txt idor.txt ssrf.txt xss.txt interestingparams.txt; do
    [ -f "$f" ] && echo "      $f — $(wc -l < "$f" | tr -d ' ') lines"
done
echo "    EXECUTION LOG:"
[ -f "$STEP_LOG" ] && echo "      $STEP_LOG — $(wc -l < "$STEP_LOG" | tr -d ' ') lines"
echo ""
echo "[+] ALL findings consolidated in fullreport.txt — one document per target."
