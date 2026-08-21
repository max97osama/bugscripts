#!/bin/bash

# Combined injection-scan stage (XSS + SQLi + Command Injection + HTTP Smuggling).
# Usage: dsxssrecon <parameters.txt> [payload_list.txt] [target_hosts.txt]

INPUT="${1:-parameters.txt}"
PAYLOADS_FILE="${2:-}"
HOSTS_FILE="${3:-subdomains.txt}"

XSS_OUT="xssreport.txt"
SQL_OUT="sqlreport.txt"
CMDI_OUT="cmdireport.txt"
SMUG_OUT="smugglerreport.txt"

> "$XSS_OUT"
> "$SQL_OUT"
> "$CMDI_OUT"
> "$SMUG_OUT"

echo "================================================================" > "$SQL_OUT"
echo "SQL INJECTION REPORT - $(date)" >> "$SQL_OUT"
echo "================================================================" >> "$SQL_OUT"

echo "================================================================" > "$CMDI_OUT"
echo "COMMAND INJECTION REPORT - $(date)" >> "$CMDI_OUT"
echo "================================================================" >> "$CMDI_OUT"

echo "================================================================" > "$SMUG_OUT"
echo "HTTP SMUGGLING REPORT - $(date)" >> "$SMUG_OUT"
echo "================================================================" >> "$SMUG_OUT"

USE_PAYLOADS=0
FIRST_PAYLOAD=""

if [ -n "$PAYLOADS_FILE" ] && [ -f "$PAYLOADS_FILE" ] && [ -s "$PAYLOADS_FILE" ]; then
    USE_PAYLOADS=1
    FIRST_PAYLOAD=$(head -n 1 "$PAYLOADS_FILE")
fi

# ---------- XSS ----------
echo "[*] XSS scan on $INPUT ..."
while IFS= read -r url; do
    [ -z "$url" ] && continue

    if [ "$USE_PAYLOADS" -eq 1 ]; then
        DALFOX_OUT=$(dalfox url "$url" --silence --no-color --skip-bav --custom-payload "$PAYLOADS_FILE" --only-custom-payload 2>/dev/null)
    else
        DALFOX_OUT=$(dalfox url "$url" --silence --no-color --skip-bav 2>/dev/null)
    fi
    echo "$DALFOX_OUT" | grep -E "^\[POC\]" | while IFS= read -r line; do
        echo "[Dalfox] $url" >> "$XSS_OUT"
        echo "$line" >> "$XSS_OUT"
        echo "" >> "$XSS_OUT"
    done

    if [ "$USE_PAYLOADS" -eq 1 ]; then
        XSS2_OUT=$(xsstrike -u "$url" --skip-dom --console-log-level 0 --payload-list "$PAYLOADS_FILE" 2>/dev/null)
    else
        XSS2_OUT=$(xsstrike -u "$url" --skip-dom --console-log-level 0 2>/dev/null)
    fi
    if echo "$XSS2_OUT" | grep -qi "Vulnerable webpage"; then
        echo "[XSStrike] $url" >> "$XSS_OUT"
        echo "$XSS2_OUT" | grep -iE "Payload|Vulnerable webpage|Confidence" >> "$XSS_OUT"
        echo "" >> "$XSS_OUT"
    fi

    sleep 2
done < "$INPUT"

# ---------- SQLi ----------
echo "[*] SQL injection scan on $INPUT ..."
if command -v sqlmap >/dev/null 2>&1; then
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        SQLMAP_OUT=$(sqlmap -u "$url" --batch --random-agent --level=2 --risk=1 --flush-session --disable-coloring 2>/dev/null)
        if echo "$SQLMAP_OUT" | grep -q "sqlmap identified the following injection point"; then
            echo "URL: $url" >> "$SQL_OUT"
            echo "Vulnerability: SQL Injection" >> "$SQL_OUT"
            echo "$SQLMAP_OUT" | grep -iE "Parameter:|Type:|Title:|Payload:" >> "$SQL_OUT"
            echo "" >> "$SQL_OUT"
        fi
        sleep 3
    done < "$INPUT"
fi

if command -v crlfuzz >/dev/null 2>&1; then
    echo "[*] CRLF injection check..."
    CRLF_OUT=$(crlfuzz -l "$INPUT" -s -t 5 2>/dev/null)
    [ -n "$CRLF_OUT" ] && echo "$CRLF_OUT" >> "$SQL_OUT"
fi

# ---------- Command injection ----------
echo "[*] Command injection scan on $INPUT ..."
if command -v commix >/dev/null 2>&1; then
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        COMMIX_OUT=$(commix -u "$url" --batch --level=1 --time-sec=5 --skip-waf --no-logging 2>/dev/null)
        if echo "$COMMIX_OUT" | grep -qiE "is vulnerable|injectable|target url is vulnerable"; then
            echo "[Commix] $url" >> "$CMDI_OUT"
            echo "$COMMIX_OUT" | grep -iE "is vulnerable|injectable|technique|payload|parameter" >> "$CMDI_OUT"
            echo "" >> "$CMDI_OUT"
        fi
        sleep 4
    done < "$INPUT"
fi

# ---------- HTTP smuggling ----------
echo "[*] HTTP smuggling scan on $HOSTS_FILE ..."
if command -v smuggler >/dev/null 2>&1; then
    while IFS= read -r host; do
        host=$(echo "$host" | tr -d '[:space:]')
        [ -z "$host" ] && continue
        if echo "$host" | grep -q "^http"; then
            TARGET_HTTP="$host"
        else
            TARGET_HTTP="https://$host"
        fi
        SMUG_OUTV=$(smuggler -u "$TARGET_HTTP" --quiet --timeout 10 2>/dev/null)
        if echo "$SMUG_OUTV" | grep -qiE "vulnerable|CL.TE|TE.CL|TE.TE"; then
            echo "[Smuggler] $TARGET_HTTP" >> "$SMUG_OUT"
            echo "$SMUG_OUTV" | grep -iE "vulnerable|CL.TE|TE.CL|TE.TE" >> "$SMUG_OUT"
            echo "" >> "$SMUG_OUT"
        fi
        sleep 5
    done < "$HOSTS_FILE"
fi

echo "[+] Done."
echo "[+] xssreport.txt: $(wc -l < "$XSS_OUT") lines"
echo "[+] sqlreport.txt: $(wc -l < "$SQL_OUT") lines"
echo "[+] cmdireport.txt: $(wc -l < "$CMDI_OUT") lines"
echo "[+] smugglerreport.txt: $(wc -l < "$SMUG_OUT") lines"

{
    echo ""
    echo "========================================================================="
    echo " [dsxssrecon] INJECTION SCANS $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================================================="
    echo "[*] XSS report       : $(wc -l < "$XSS_OUT" | tr -d ' ') lines"
    echo "[*] SQL report       : $(wc -l < "$SQL_OUT" | tr -d ' ') lines"
    echo "[*] Command-inj report: $(wc -l < "$CMDI_OUT" | tr -d ' ') lines"
    echo "[*] Smuggling report : $(wc -l < "$SMUG_OUT" | tr -d ' ') lines"
    echo ""
    for rep in "$XSS_OUT" "$SQL_OUT" "$CMDI_OUT" "$SMUG_OUT"; do
        if [ -s "$rep" ]; then
            echo "--- $rep ---"
            grep -iE "vulnerable|CVE|inject|payload|UID|Payload" "$rep" 2>/dev/null | head -30
            echo ""
        fi
    done
    echo ""
} >> fullreport.txt 2>/dev/null
