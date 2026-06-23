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
log "ASSETFINDER"
log "================================================================"

assetfinder --subs-only "$DOMAIN" > /tmp/assetfinder_$$.txt 2>/dev/null
cat /tmp/assetfinder_$$.txt >> "$REPORT"
log "[+] Assetfinder found $(wc -l < /tmp/assetfinder_$$.txt) assets"

sleep 5

log ""
log "================================================================"
log "KITERUNNER"
log "================================================================"

while IFS= read -r TARGET; do
    log "[*] Kiterunner scanning: $TARGET"
    kr scan "$TARGET" \
        -w "$KITE_WORDLIST" \
        --delay 500ms \
        --parallelism 1 \
        --timeout 10s \
        -o text \
        2>/dev/null | tee -a /tmp/kite_$$.txt >> "$REPORT"

    grep -E "GET|POST|PUT|DELETE" /tmp/kite_$$.txt | \
        grep -v "404\|Not Found" | \
        awk '{print $NF}' >> "$VULN_URLS"

    sleep 8
done < "$TARGETS"

sleep 5

log ""
log "================================================================"
log "ARJUN - PARAMETER DISCOVERY"
log "================================================================"

> /tmp/arjun_all_$$.txt

while IFS= read -r TARGET; do
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

    sleep 8
done < "$TARGETS"

sleep 5

log ""
log "================================================================"
log "LINKFINDER"
log "================================================================"

while IFS= read -r TARGET; do
    log "[*] Linkfinder scanning: $TARGET"
    linkfinder \
        -i "$TARGET" \
        -d \
        -o cli \
        2>/dev/null | tee -a /tmp/linkfinder_$$.txt >> "$REPORT"
    sleep 8
done < "$TARGETS"

grep -E "^http|^/" /tmp/linkfinder_$$.txt 2>/dev/null | \
    grep -iE "admin|api|upload|config|backup|debug|test|dev|secret|key|token|login|auth|passwd|password|\.env|\.git|\.sql|\.bak" \
    >> "$VULN_URLS"

sleep 5

log ""
log "================================================================"
log "SECRETFINDER"
log "================================================================"

while IFS= read -r TARGET; do
    log "[*] SecretFinder scanning: $TARGET"
    secretfinder \
        -i "$TARGET" \
        -e \
        -o cli \
        2>/dev/null | tee -a /tmp/secretfinder_$$.txt >> "$REPORT"
    sleep 8
done < "$TARGETS"

grep -iE "api_key|secret|token|password|aws|private|auth|bearer|jwt" \
    /tmp/secretfinder_$$.txt 2>/dev/null >> "$VULN_URLS"

sleep 5

log ""
log "================================================================"
log "QSREPLACE - PARAMETER INJECTION TEST"
log "================================================================"

if [ -s /tmp/arjun_all_$$.txt ]; then
    grep -oE "https?://[^ ]+" /tmp/arjun_all_$$.txt | sort -u > /tmp/param_urls_$$.txt

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
fi

sleep 5

log ""
log "================================================================"
log "ORALYZER - OPEN REDIRECT CHECK"
log "================================================================"

if [ -f /tmp/param_urls_$$.txt ]; then
    oralyzer \
        -l /tmp/param_urls_$$.txt \
        2>/dev/null | tee -a /tmp/oralyzer_$$.txt >> "$REPORT"

    grep -iE "vulnerable|redirect|open redirect" \
        /tmp/oralyzer_$$.txt 2>/dev/null >> "$VULN_URLS"
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

rm -f "$TARGETS" /tmp/assetfinder_$$.txt /tmp/kite_$$.txt \
    /tmp/arjun_all_$$.txt /tmp/linkfinder_$$.txt /tmp/secretfinder_$$.txt \
    /tmp/param_urls_$$.txt /tmp/qsreplace_$$.txt /tmp/oralyzer_$$.txt