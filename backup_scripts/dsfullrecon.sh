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

RUN_DIR="${BASE_NAME}_recon"
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
    step "STEP 1" "Passive subdomain recon (dsPassiveSubRecon)"
    run dspassivesubrecon "$DOMAIN" "$SUBDOMAINS_FILE"

    step "STEP 2" "Aggregated passive sources (SecurityTrails, OTX, crt.sh, RapidDNS, Shodan)"
    run dspassivesources "$DOMAIN" "$SUBDOMAINS_FILE"

    step "STEP 3" "Active subdomain bruteforce"
    if [ -f "$SUBS_WORDLIST" ] && [ -s "$SUBS_WORDLIST" ]; then
        run dsbrutesubrecon "$DOMAIN" "$SUBS_WORDLIST" "$SUBDOMAINS_FILE"
    else
        echo "[-] Brute skipped: provide subdomains wordlist arg. (example: /root/wordlist/shorts/subdomains.txt)" | tee -a "$STEP_LOG"
    fi
fi

step "STEP 4" "Resolve real IPs + filter alive subdomains (dsIPRecon)"
run dsiprecon "$SUBDOMAINS_FILE"
if has_file "activesubs.txt"; then
    cp activesubs.txt "$SUBDOMAINS_FILE"
    echo "[+] subdomains.txt updated with alive subdomains only." | tee -a "$STEP_LOG"
fi

step "STEP 5" "Find origin IPs behind CDN (dsOriginIP)"
run dsoriginip "$SUBDOMAINS_FILE"

step "STEP 6" "Tech stack + WAF + headers fingerprinting (dsTechRecon)"
run dstechrecon "$SUBDOMAINS_FILE"

step "STEP 7" "Web security headers / WAF audit (dsWebRecon)"
run dswebrecon "$SUBDOMAINS_FILE"

step "STEP 8" "Nmap vulnerability scan on each real IP (dsNmapScan)"
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

step "STEP 9" "Subdomain takeover detection (dsTakeover)"
run dstakeover "$SUBDOMAINS_FILE"

step "STEP 10" "URL gathering from archives (dsURLRecon)"
run dsurlrecon "$DOMAIN" -l "$SUBDOMAINS_FILE"

step "STEP 11" "Wayback/archive diff + live filter (dsParalytics)"
run dsparalytics "$SUBDOMAINS_FILE"

step "STEP 12" "Directory & file bruteforce (dsDirRecon)"
if [ -f "$DIR_WORDLIST" ] && [ -s "$DIR_WORDLIST" ]; then
    run dsdirrecon "$DOMAIN" "$SUBDOMAINS_FILE" "$DIR_WORDLIST"
    if has_file "burl.txt"; then
        cat burl.txt >> "$URLS_FILE"
        echo "[+] burl.txt appended to urls.txt" | tee -a "$STEP_LOG"
    fi
else
    echo "[-] Dir brute skipped: provide dir wordlist arg. (example: /root/wordlist/shorts/dir.txt)" | tee -a "$STEP_LOG"
fi

step "STEP 13" "Crawling (dsCrawlRecon)"
if [ -f "$DIR_WORDLIST" ] && [ -s "$DIR_WORDLIST" ]; then
    run dscrawlrecon "$SUBDOMAINS_FILE" 3 "$DIR_WORDLIST"
else
    run dscrawlrecon "$DOMAIN" 3 ""
fi

step "STEP 14" "Find URLs from JS and pages (dsFindRecon)"
run dsfindrecon "$SUBDOMAINS_FILE"
if has_file "findurls.txt"; then
    cat findurls.txt >> "$URLS_FILE"
    echo "[+] findrecon findurls.txt appended to urls.txt" | tee -a "$STEP_LOG"
fi

step "STEP 15" "JS endpoints + secrets extraction (dsJSEndpoints)"
run dsjsendpoints "$SUBDOMAINS_FILE"

step "STEP 16" "API recon / parameter discovery (dsAPIRecon)"
if [ -f "$KITE_WORDLIST" ] && [ -s "$KITE_WORDLIST" ]; then
    run dsapirecon "$DOMAIN" "$SUBDOMAINS_FILE" "$KITE_WORDLIST"
    if has_file "vulnerable_urls.txt"; then
        cat vulnerable_urls.txt >> "$URLS_FILE"
        echo "[+] vulnerable_urls.txt appended to urls.txt" | tee -a "$STEP_LOG"
    fi
else
    echo "[-] API recon skipped: provide kite wordlist arg. (example: /root/wordlist/large.kite)" | tee -a "$STEP_LOG"
fi

step "STEP 17" "Clean and deduplicate URLs"
run dscleanurls "$URLS_FILE"

step "STEP 18" "Filter URLs into js.txt / parameters.txt / cleaned (dsURLFilter)"
run dsurlfilter "$URLS_FILE"
run dsclassifyurls "$URLS_FILE" "$DOMAIN"

step "STEP 19" "JS secret scan on js files (dsReconFilter)"
if has_file "js.txt"; then
    run dsreconfilter "$URLS_FILE"
fi

step "STEP 20" "Exposed .git / .env / backup files (dsGitRecon)"
run dsgitrecon "$SUBDOMAINS_FILE"

step "STEP 21" "GraphQL introspection check (dsGraphQLRecon)"
run dsgraphqlrecon "$SUBDOMAINS_FILE"

step "STEP 22" "Cloud storage misconfig check (dsCloudPermissions)"
run dscloudpermissions "$SUBDOMAINS_FILE"

step "STEP 23" "Header injection / CRLF / open redirect (dsHeaderInject)"
run dsheaderinject "$URLS_FILE"

step "STEP 24" "JWT analysis (dsJWTCheck)"
if has_file "js.txt"; then
    run dsjwtcheck "js.txt"
fi

step "STEP 25" "XSS scan on parameters (dsXSSRecon)"
if has_file "$PARAMS_FILE"; then
    run dsxssrecon "$PARAMS_FILE"
else
    echo "[-] XSS skipped: no parameters.txt." | tee -a "$STEP_LOG"
fi

step "STEP 26" "SQL injection scan (dsSQLRecon)"
if has_file "$PARAMS_FILE"; then
    run dssqlrecon "$PARAMS_FILE"
else
    echo "[-] SQL skipped: no parameters.txt." | tee -a "$STEP_LOG"
fi

step "STEP 27" "Command injection scan (dsCommixRecon)"
if has_file "$PARAMS_FILE"; then
    run dscommixrecon "$PARAMS_FILE"
else
    echo "[-] Commix skipped: no parameters.txt." | tee -a "$STEP_LOG"
fi

step "STEP 28" "HTTP request smuggling scan (dsSmugglerRecon)"
run dssmugglerrecon "$SUBDOMAINS_FILE"

step "DONE" "Full recon complete"
echo ""
echo "[+] Output files summary (run dir: $(pwd)):"
for f in subdomains.txt activesubs.txt ips.txt ipsv6.txt origin_ips.txt urlrecon.txt urls.txt curls.txt \
          findurls.txt burl.txt parameters.txt js.txt tech.txt techstack.txt webrecon.txt waf.txt \
          techsummary.txt graphql_report.txt cloudreport.txt gitrecon.txt headerinject.txt takeovers.txt \
          jwt.json jwtreport.txt endpoints.txt jsecrets.txt xssreport.txt sqlreport.txt cmdireport.txt \
          smugglerreport.txt recon_steps.txt; do
    if has_file "$f"; then
        echo "    $f — $(wc -l < "$f") lines"
    fi
done
