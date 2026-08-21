#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <urls.txt> [target_domain]"
    exit 1
fi

INPUT="$1"
TARGET_DOMAIN="$2"

if [ ! -f "$INPUT" ]; then
    echo "[-] $INPUT not found."
    exit 1
fi

TEMP1="/tmp/clean1_$$.txt"
TEMP2="/tmp/clean2_$$.txt"

grep -oE "(https?://[a-zA-Z0-9./_:@?=&%+~#-]+|www\.[a-zA-Z0-9./_:@?=&%+~#-]+|[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}(/[a-zA-Z0-9./_:@?=&%+~#-]*)?)" "$INPUT" > "$TEMP1"

if [ -n "$TARGET_DOMAIN" ]; then
    grep -iF "$TARGET_DOMAIN" "$TEMP1" > /tmp/urlfilter_scope_$$.txt
    mv /tmp/urlfilter_scope_$$.txt "$TEMP1" 2>/dev/null
fi

grep -vE "^\s*$|^[0-9]+$|\.(jpg|jpeg|png|gif|svg|ico|bmp|webp|woff|woff2|ttf|eot|pdf|mp4|mp3)$" "$TEMP1" | \
    grep -E "\.[a-zA-Z]{2,}" > "$TEMP2"

sort -u "$TEMP2" -o "$TEMP2"

uro -i "$TEMP2" -o "$INPUT" 2>/dev/null

if [ ! -s "$INPUT" ]; then
    cp "$TEMP2" "$INPUT"
fi

sort -u "$INPUT" -o "$INPUT"

grep -iE "\.js(\?.*)?$" "$INPUT" > js.txt
grep -iE "\?[^=]+=|&[^=]+=" "$INPUT" > parameters.txt
grep -viE "\.(js|css|jpg|jpeg|png|gif|svg|ico|webp|bmp|tiff|woff|woff2|ttf|eot|json)(\?.*)?$" "$INPUT" > cleaned.txt

grep -ivE "\.(js|css|jpg|jpeg|png|gif|svg|ico|bmp|webp|csv|json|woff|woff2|ttf|eot|pdf|mp4|mp3|zip|tar|gz|xml|rss)(\?.*)?$" "$INPUT" > interesting.txt

echo "[+] Done. Clean unique URLs in $INPUT: $(wc -l < "$INPUT")"
echo "[+] js.txt: $(wc -l < js.txt)"
echo "[+] parameters.txt: $(wc -l < parameters.txt)"
echo "[+] cleaned.txt: $(wc -l < cleaned.txt)"
echo "[+] interesting.txt: $(wc -l < interesting.txt)"

echo "[*] Classifying URLs by vuln class (gf)..."
SCOPED="/tmp/urlfilter_classify_$$.txt"
if [ -n "$TARGET_DOMAIN" ]; then
    grep -iF "$TARGET_DOMAIN" "$INPUT" > "$SCOPED"
else
    cp "$INPUT" "$SCOPED"
fi

for p in sqli xxe ssti redirect rce lfi idor ssrf xss interestingEXT interestingparams backup; do
    OUT="${p}.txt"
    > "$OUT"
    if command -v gf >/dev/null 2>&1 && [ -f ~/.gf/${p}.json ]; then
        gf "$p" "$SCOPED" >> "$OUT" 2>/dev/null
    fi
    if [ -s "$OUT" ]; then
        sort -u "$OUT" -o "$OUT"
        echo "[+] ${p}.txt: $(wc -l < "$OUT") URLs"
    fi
done

grep -iE "(\?|&)(file|path|url|next|redirect|dest|return|target|token|secret|key|password|email|user|id|page|dir|cmd|exec|q|search|query|callback|ref|data|msg|url1|out)" "$SCOPED" >> interestingparams.txt 2>/dev/null

echo "[*] Scanning JS files for secrets (reconfilter logic)..."
ALLJS="alljs.txt"
FINDINGS="Findings.txt"
JSECRETS="jsecrets.txt"
> "$ALLJS"
> "$FINDINGS"
> "$JSECRETS"

PATTERN='(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|secret|password|passwd|pwd|access[_-]?key|access[_-]?token|auth[_-]?token|authorization|bearer|client[_-]?secret|private[_-]?key|aws_access_key_id|aws_secret_access_key|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|firebase|mongodb\+srv|x-api-key)'
STRICT_PATTERN='(AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|mongodb\+srv://[^[:space:]"'"'"']+|(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|secret|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|x-api-key)[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9_.\/+=-]{10,}["'"'"'])'
FALSE_POSITIVE='(your[_-]?(api)?[_-]?key|xxxxxxxx|00000000|changeme|example\.com|placeholder|dummy|test[_-]?key|\{\{|\$\{|<[a-zA-Z])'

if [ -s js.txt ]; then
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        CONTENT=$(timeout 20 curl -s --max-time 15 "$url")
        echo "$CONTENT" >> "$ALLJS"
        echo "$CONTENT" | grep -inE "$PATTERN" | while IFS= read -r line; do
            echo "URL: $url" >> "$FINDINGS"
            echo "$line" >> "$FINDINGS"
            echo "" >> "$FINDINGS"
        done
        echo "$CONTENT" | grep -inE "$STRICT_PATTERN" | grep -viE "$FALSE_POSITIVE" | while IFS= read -r line; do
            echo "URL: $url" >> "$JSECRETS"
            echo "$line" >> "$JSECRETS"
            echo "" >> "$JSECRETS"
        done
    done < js.txt
    sort -u "$ALLJS" -o "$ALLJS"
    echo "[+] alljs.txt: $(wc -l < "$ALLJS") lines"
    echo "[+] Findings.txt entries: $(grep -c '^URL:' "$FINDINGS")"
    echo "[+] jsecrets.txt entries: $(grep -c '^URL:' "$JSECRETS")"
else
    echo "[-] No js.txt present to scan for secrets."
fi

{
    echo ""
    echo "========================================================================="
    echo " [dsurlfilter] FILTER / CLASSIFY / SECRET-SCAN $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================================================="
    echo "[*] parameters.txt : $(wc -l < parameters.txt 2>/dev/null | tr -d ' ')"
    echo "[*] cleaned.txt    : $(wc -l < cleaned.txt 2>/dev/null | tr -d ' ')"
    echo "[*] js.txt         : $(wc -l < js.txt 2>/dev/null | tr -d ' ')"
    echo "[*] Findings.txt   : $(grep -c '^URL:' Findings.txt 2>/dev/null) secret hits"
    echo "[*] Classified URL counts:"
    for p in sqli xxe ssti redirect rce lfi idor ssrf xss; do
        [ -s "$p.txt" ] && echo "    ${p}.txt : $(wc -l < "$p.txt" | tr -d ' ')"
    done
    echo ""
} >> fullreport.txt 2>/dev/null

rm -f "$TEMP1" "$TEMP2" "$SCOPED"
