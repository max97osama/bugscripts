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

sort -u "$VULN_URLS" -o "$VULN_URLS"

log ""
log "================================================================"
log "FINAL SUMMARY"
log "================================================================"
log "[+] Scan complete for: $DOMAIN"
log "[+] Vulnerable/interesting URLs found: $(wc -l < "$VULN_URLS")"
log "[+] Vulnerable URLs saved to: $VULN_URLS"
log "[+] Full report saved to: $REPORT"

rm -f "$TARGETS" /tmp/kite_$$.txt \
    /tmp/arjun_all_$$.txt \
    /tmp/param_urls_$$.txt /tmp/qsreplace_$$.txt /tmp/oralyzer_$$.txt \
    /tmp/openredirex_urls_$$.txt /tmp/openredirex_$$.txt
