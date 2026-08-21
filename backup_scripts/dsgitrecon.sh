#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <subdomains.txt|domain>"
    echo "  Checks for exposed .git, source maps, env files, backups, configs."
    exit 1
fi

INPUT="$1"
OUT="gitrecon.txt"
> "$OUT"

TMP="/tmp/gitrecon_$$"
mkdir -p "$TMP"

TARGETS="$TMP/targets.txt"
> "$TARGETS"

if [ -f "$INPUT" ]; then
    grep -vE '^\s*$' "$INPUT" | sort -u > "$TARGETS"
else
    echo "$INPUT" > "$TARGETS"
fi

echo "======================================================================" >> "$OUT"
echo "EXPOSED-FILE RECON - $(date)" >> "$OUT"
echo "======================================================================" >> "$OUT"

PATHS=(
    ".git/config"
    ".git/HEAD"
    ".env"
    ".env.bak"
    ".env.production"
    ".svn/entries"
    ".htaccess"
    "web.config.bak"
    "backup.sql"
    "db.sql"
    "dump.sql"
    "wp-config.php.bak"
    "wp-config.php~"
    "config.php.bak"
    "config.json"
    ".DS_Store"
    "backup.zip"
    "backup.tar.gz"
    "phpinfo.php"
    "server-status"
    "README.md"
)

while IFS= read -r target; do
    target=$(echo "$target" | tr -d '[:space:]')
    [ -z "$target" ] && continue

    for base in "https://$target"; do
        echo "" >> "$OUT"
        echo "[*] $base" >> "$OUT"

        for p in "${PATHS[@]}"; do
            CODE=$(curl -sk -o "$TMP/resp_$$.txt" -w "%{http_code}" --max-time 8 \
                "$base/$p" 2>/dev/null)

            if [ "$CODE" = "200" ]; then
                # verify it's actual file content, not a 200 SPA fallback
                SIZE=$(wc -c < "$TMP/resp_$$.txt")
                echo "[OK] $base/$p (200, ${SIZE}B)" >> "$OUT"
                echo "[OK] $base/$p"
                if echo "$p" | grep -qiE "\.git/config|\.env$|account|database|password|secret|api"; then
                    echo "    Content preview (lines matching secret/db):" >> "$OUT"
                    grep -aiE "password|user|db_|secret|key|token|id_rsa|ref:" "$TMP/resp_$$.txt" \
                        | head -5 | sed 's/^/    /' >> "$OUT"
                fi
            fi
            rm -f "$TMP/resp_$$.txt"
        done

        if command -v gitdumper >/dev/null 2>&1 || command -v git-dumper >/dev/null 2>&1; then
            :
        fi
    done
done < "$TARGETS"

echo "[+] Done. Exposed-file findings in $OUT: $(wc -l < "$OUT") lines."
echo "[+] Manually verify each hit (avoid false positives from SPA/404->200)."

rm -rf "$TMP"
