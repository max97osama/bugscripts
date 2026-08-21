#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <urls.txt> [target_domain]"
    echo "  Uses gf to split urls.txt into per-vuln-class files."
    exit 1
fi

INPUT="$1"
TARGET_DOMAIN="$2"

PATTERNS=(sqli xxe ssti redirect rce lfi idor ssrf xss interestingEXT interestingparams backup)

for p in "${PATTERNS[@]}"; do
    OUT="${p}.txt"
    > "$OUT"
done

if [ -n "$TARGET_DOMAIN" ]; then
    grep -iF "$TARGET_DOMAIN" "$INPUT" > /tmp/classify_scope_$$.txt
    SCOPED="/tmp/classify_scope_$$.txt"
else
    SCOPED="$INPUT"
fi

for p in "${PATTERNS[@]}"; do
    if command -v gf >/dev/null 2>&1 && [ -f ~/.gf/${p}.json ]; then
        gf "$p" "$SCOPED" >> "${p}.txt" 2>/dev/null
    else
        echo "[-] gf pattern '$p' missing, skipping."
    fi
done

# General high-signal params even if no gf pattern matches
grep -iE "(\?|&)(file|path|url|next|redirect|dest|return|target|token|secret|key|password|email|user|id|page|dir|cmd|exec|q|search|query|callback|ref|data|msg|url1|out)" "$SCOPED" >> interestingparams.txt 2>/dev/null

for p in "${PATTERNS[@]}"; do
    if [ -s "${p}.txt" ]; then
        sort -u "${p}.txt" -o "${p}.txt"
        echo "[+] ${p}.txt: $(wc -l < "${p}.txt") URLs"
    fi
done

rm -f /tmp/classify_scope_$$.txt

echo "[+] Done. Feed the classified .txt files to matching scanners (e.g. dalfox on xss.txt, sqlmap/gf sqli.txt)."
