#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <domain> <subdomains.txt> <kite_wordlist>"
    exit 1
fi

DOMAIN="$1"
SUBDOMAINS_FILE="$2"
KITE_WORDLIST="$3"

REPORT="report.txt"
VULN_URLS="vulnerable_urls.txt"

> "$REPORT"
> "$VULN_URLS"

TARGETS="/tmp/targets_$$.txt"
> "$TARGETS"

echo "https://$DOMAIN" >> "$TARGETS"
while IFS= read -r sub; do
    sub=$(echo "$sub" | tr -d '[:space:]')
    [ -z "$sub" ] && continue
    if echo "$sub" | grep -q "^http"; then
        echo "$sub" >> "$TARGETS"
    else
        echo "https://$sub" >> "$TARGETS"
    fi
done < "$SUBDOMAINS_FILE"

sort -u "$TARGETS" -o "$TARGETS"

log() {
    echo "$1"
    echo "$1" >> "$REPORT"
}

log "================================================================"
log "RECON REPORT FOR: $DOMAIN"
log "Date: $(date)"
log "================================================================"

log ""
log "================================================================"
log "KITERUNNER"
log "================================================================"

while IFS= read -r TARGET; do
    if command -v kr >/dev/null 2>&1 || command -v kiterunner >/dev/null 2>&1; then
        KR_BIN=$(command -v kr || command -v kiterunner)
        log "[*] Kiterunner scanning: $TARGET"
        "$KR_BIN" scan "$TARGET" \
            -w "$KITE_WORDLIST" \
            --delay 500ms \
            --parallelism 1 \
            --timeout 10s \
            -o text \
            2>/dev/null | tee -a /tmp/kite_$$.txt >> "$REPORT"

        grep -E "GET|POST|PUT|DELETE" /tmp/kite_$$.txt | \
            grep -v "404\|Not Found" | \
            awk '{print $NF}' >> "$VULN_URLS"
    else
        log "[-] kiterunner not found on PATH, skipping $TARGET"
    fi

    sleep 8
done < "$TARGETS"

sleep 5

log ""
log "================================================================"
log "X8 - HIDDEN PARAMETER DISCOVERY"
log "================================================================"
log "[*] x8 finds hidden/undocumented parameters on live endpoints (often reveals IDOR/SSRF/SQLi/access-control bugs)"

if command -v x8 >/dev/null 2>&1; then
    X8_OUT="/tmp/x8_$$.txt"
    X8_WORDLIST="${X8_WORDLIST:-}"
    > "$X8_OUT"
    while IFS= read -r TARGET; do
        TARGET=$(echo "$TARGET" | tr -d '[:space:]')
        [ -z "$TARGET" ] && continue
        echo "[*] x8 scanning: $TARGET"
        [ -z "$X8_WORDLIST" ] && [ -f /root/wordlist/x8/params.txt ] && X8_WORDLIST=/root/wordlist/x8/params.txt
        if [ -n "$X8_WORDLIST" ] && [ -f "$X8_WORDLIST" ]; then
            timeout 240 x8 -u "$TARGET" \
                -w "$X8_WORDLIST" \
                -o "$X8_OUT" \
                -L \
                -H "User-Agent: Mozilla/5.0" \
                --timeout 10 \
                --disable-colors \
                2>/dev/null
        else
            timeout 240 x8 -u "$TARGET" \
                -o "$X8_OUT" \
                -L \
                -H "User-Agent: Mozilla/5.0" \
                --timeout 10 \
                --disable-colors \
                --custom-parameters "admin debug test id uid token key page user" \
                2>/dev/null
        fi
        sleep 5
    done < "$TARGETS"

    if [ -f "$X8_OUT" ] && [ -s "$X8_OUT" ]; then
        cat "$X8_OUT" >> "$REPORT"
        grep -oE "https?://[^ ]+" "$X8_OUT" | sort -u >> "$VULN_URLS"
        log "[+] x8 found hidden params/results; see X8 section in $REPORT"
    else
        log "[-] x8 produced no parameter findings (checked each target)."
    fi
    rm -f "$X8_OUT"
else
    log "[-] x8 not found on PATH, skipping hidden-parameter discovery."
fi

sleep 5

log ""
log "================================================================"
log "ARJUN - PARAMETER DISCOVERY"
log "================================================================"

> /tmp/arjun_all_$$.txt

while IFS= read -r TARGET; do
    if command -v arjun >/dev/null 2>&1; then
        log "[*] Arjun scanning: $TARGET"
        arjun -u "$TARGET" \
            -t 1 \
            --delay 3 \
            --passive \
            -oT /tmp/arjun_temp_$$.txt \
            2>/dev/null

        if [ -f /tmp/arjun_temp_$$.txt ]; then
            cat /tmp/arjun_temp_$$.txt >> "$REPORT"
            cat /tmp/arjun_temp_$$.txt >> /tmp/arjun_all_$$.txt
            rm -f /tmp/arjun_temp_$$.txt
        fi
    else
        log "[-] arjun not found on PATH, skipping $TARGET"
    fi

    sleep 8
done < "$TARGETS"

sleep 5

log ""
log "================================================================"
log "QSREPLACE - PARAMETER INJECTION TEST"
log "================================================================"

if [ -s /tmp/arjun_all_$$.txt ]; then
    grep -oE "https?://[^ ]+" /tmp/arjun_all_$$.txt | sort -u > /tmp/param_urls_$$.txt

    if command -v qsreplace >/dev/null 2>&1; then
        cat /tmp/param_urls_$$.txt | \
            qsreplace "FUZZ" | sort -u > /tmp/qsreplace_$$.txt

        cat /tmp/qsreplace_$$.txt >> "$REPORT"

        while IFS= read -r url; do
            STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
                --max-time 10 \
                --connect-timeout 5 \
                -A "Mozilla/5.0" \
                "$url")
            if echo "$STATUS" | grep -qE "^(200|301|302|403|500)$"; then
                echo "$url [$STATUS]" | tee -a "$REPORT" >> "$VULN_URLS"
            fi
            sleep 3
        done < /tmp/qsreplace_$$.txt
    else
        log "[-] qsreplace not found on PATH, skipping parameter injection test."
    fi
fi

sleep 5

log ""
log "================================================================"
log "ORALYZER - OPEN REDIRECT CHECK"
log "================================================================"

if [ -f /tmp/param_urls_$$.txt ]; then
    if [ -f /usr/local/bin/Oralyzer/oralyzer.py ]; then
        python3 /usr/local/bin/Oralyzer/oralyzer.py \
            -l /tmp/param_urls_$$.txt \
            2>/dev/null | tee -a /tmp/oralyzer_$$.txt >> "$REPORT"

        grep -iE "vulnerable|redirect|open redirect" \
            /tmp/oralyzer_$$.txt 2>/dev/null >> "$VULN_URLS"
    else
        log "[-] Oralyzer not found at /usr/local/bin/Oralyzer/oralyzer.py, skipping."
    fi
fi

sleep 5

log ""
log "================================================================"
log "OPENREDIREX - OPEN REDIRECT FUZZING"
log "================================================================"

if [ -f /tmp/param_urls_$$.txt ]; then
    grep -iE "url=|redirect=|return=|next=|dest=|target=|rurl=|redir=|continue=" \
        /tmp/param_urls_$$.txt 2>/dev/null | \
        sed -E 's/(url=|redirect=|return=|next=|dest=|target=|rurl=|redir=|continue=)[^&]*/\1FUZZ/gi' \
        > /tmp/openredirex_urls_$$.txt

    OPENREDIREX_PAYLOADS="/tmp/openredirex_payloads_$$.txt"
    cat > "$OPENREDIREX_PAYLOADS" << 'PAYLOADS'
//evil.com
https://evil.com
//google.com%252F@evil.com
https:evil.com
/\evil.com
////evil.com
PAYLOADS

    if [ -s /tmp/openredirex_urls_$$.txt ] && command -v openredirex >/dev/null 2>&1; then
        while IFS= read -r target_url; do
            echo "$target_url" | openredirex \
                -p "$OPENREDIREX_PAYLOADS" \
                -k FUZZ \
                -c 20 \
                2>/dev/null | tee -a /tmp/openredirex_$$.txt >> "$REPORT"
            sleep 2
        done < /tmp/openredirex_urls_$$.txt

        grep -iE "vulnerable|redirect" \
            /tmp/openredirex_$$.txt 2>/dev/null >> "$VULN_URLS"
    elif [ -s /tmp/openredirex_urls_$$.txt ] && ! command -v openredirex >/dev/null 2>&1; then
        log "[-] openredirex not found on PATH, skipping open redirect fuzzing."
    fi

    rm -f "$OPENREDIREX_PAYLOADS"
fi

log ""
log "================================================================"
log "HEADER INJECTION / HOST-HEADER / OPEN REDIRECT"
log "================================================================"

HDR_INJ_OUT="headerinject.txt"
> "$HDR_INJ_OUT"

if command -v crlfuzz >/dev/null 2>&1; then
    log "[*] crlfuzz CRLF injection..."
    crlfuzz -l "$TARGETS" -s -t 5 2>/dev/null | tee -a "$HDR_INJ_OUT" >> "$REPORT"
fi

log "[*] Host-header + X-Forwarded-For reflection checks..."
while IFS= read -r TARGET; do
    TARGET=$(echo "$TARGET" | tr -d '[:space:]')
    [ -z "$TARGET" ] && continue
    RESP=$(curl -sk -o /tmp/hdr_xff_$$.txt -w "%{http_code}" --max-time 10 \
        -H "X-Forwarded-For: techinsight.test" "$TARGET" 2>/dev/null)
    if grep -qiE "techinsight\.test" /tmp/hdr_xff_$$.txt 2>/dev/null; then
        echo "[REFLECTED] X-Forwarded-For reflected: $TARGET" | tee -a "$HDR_INJ_OUT" >> "$REPORT"
    fi
    LOC=$(curl -sk -o /dev/null -D - --max-time 8 "$TARGET" 2>/dev/null | grep -i "^location:" | tr -d '\r')
    if echo "$LOC" | grep -qiE "evil|//google|javascript:|data:"; then
        echo "[OPEN-REDIRECT?] $TARGET -> $LOC" | tee -a "$HDR_INJ_OUT" >> "$REPORT"
    fi
    rm -f /tmp/hdr_xff_$$.txt
    sleep 2
done < "$TARGETS"

log ""
log "================================================================"
log "JWT EXTRACTION / ANALYSIS"
log "================================================================"

JWT_OUT="jwt.json"
JWT_REPORT="jwtreport.txt"
> "$JWT_OUT"
> "$JWT_REPORT"

grep -oE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' "$TARGETS" 2>/dev/null \
    | sort -u > /tmp/jwt_tokens_$$.txt

if [ ! -s /tmp/jwt_tokens_$$.txt ]; then
    echo "[*] Searching responses for JWTs..."
    while IFS= read -r TARGET; do
        TARGET=$(echo "$TARGET" | tr -d '[:space:]')
        [ -z "$TARGET" ] && continue
        curl -sk --max-time 12 "$TARGET" 2>/dev/null | grep -oE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' >> /tmp/jwt_tokens_$$.txt
        sleep 1
    done < "$TARGETS"
    sort -u /tmp/jwt_tokens_$$.txt -o /tmp/jwt_tokens_$$.txt 2>/dev/null
fi

if [ -s /tmp/jwt_tokens_$$.txt ]; then
    echo "Found $(wc -l < /tmp/jwt_tokens_$$.txt) JWT(s)." >> "$JWT_REPORT"
    while IFS= read -r token; do
        [ -z "$token" ] && continue
        echo "=== $token ===" >> "$JWT_REPORT"
        HEADER=$(echo "$token" | cut -d. -f1 | base64 -d 2>/dev/null)
        PAYLOAD=$(echo "$token" | cut -d. -f2 | base64 -d 2>/dev/null)
        ALG=$(echo "$HEADER" | jq -r .alg 2>/dev/null)
        echo "  Algorithm: $ALG" >> "$JWT_REPORT"
        NONEHEAD=$(python3 -c "import base64,json; print(base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('='))" 2>/dev/null)
        PAYLOAD2=$(echo "$token" | cut -d. -f2)
        echo "  PoC alg:none: ${NONEHEAD}.${PAYLOAD2}." >> "$JWT_REPORT"
    done < /tmp/jwt_tokens_$$.txt
    log "[+] JWTs analysed in $JWT_REPORT"
else
    log "[-] No JWTs found."
fi

sort -u "$VULN_URLS" -o "$VULN_URLS"

log ""
log "================================================================"
log "FINAL SUMMARY"
log "================================================================"
log "[+] Scan complete for: $DOMAIN"
if [ -s "$VULN_URLS" ]; then
    log "[+] Vulnerable/interesting URLs found: $(wc -l < "$VULN_URLS")"
    log "[+] Vulnerable URLs saved to: $VULN_URLS"
else
    log "[-] No vulnerable/interesting URLs were found (vulnerable_urls.txt not created)."
fi
log "[+] Full report saved to: $REPORT"

{
    echo ""
    echo "========================================================================="
    echo " [dsapirecon] API / HEADERS / JWT $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================================================="
    echo "[*] Vulnerable/interesting URLs : $(wc -l < "$VULN_URLS" | tr -d ' ')"
    echo ""
    echo "--- vulnerable_urls.txt ---"
    cat "$VULN_URLS" 2>/dev/null
    echo ""
    echo "--- headerinject.txt ---"
    cat "$HDR_INJ_OUT" 2>/dev/null
    echo ""
    echo "--- jwtreport.txt ---"
    cat "$JWT_REPORT" 2>/dev/null
    echo ""
} >> fullreport.txt 2>/dev/null

rm -f "$TARGETS" /tmp/kite_$$.txt \
    /tmp/arjun_all_$$.txt \
    /tmp/param_urls_$$.txt /tmp/qsreplace_$$.txt /tmp/oralyzer_$$.txt \
    /tmp/openredirex_urls_$$.txt /tmp/openredirex_$$.txt /tmp/jwt_tokens_$$.txt
