#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <subdomains.txt|domain>"
    echo "  Misc asset-specific bug checks:"
    echo "    - cloud storage misconfig (S3, Azure Blob, GCS)"
    echo "    - exposed VCS/backup/env files (.git, .env, backups)"
    echo "    - GraphQL endpoints + introspection/IDOR"
    echo "  Outputs: cloudreport.txt, gitrecon.txt, graphql_report.txt"
    exit 1
fi

INPUT="$1"
OUT="cloudreport.txt"
> "$OUT"

TMP="/tmp/cloudrecon_$$"
mkdir -p "$TMP"

APEX=$(if [ -f "$INPUT" ]; then sort -u "$INPUT" | head -1; else echo "$INPUT"; fi | sed 's/^[^.a-z]*\.//')

echo "======================================================================" >> "$OUT"
echo "CLOUD STORAGE RECON - $APEX - $(date)" >> "$OUT"
echo "======================================================================" >> "$OUT"

echo "[*] Checking S3 buckets derived from $APEX..."
for prefix in "$APEX" "www.$APEX" "assets.$APEX" "media.$APEX" "static.$APEX" "uploads.$APEX" "backup.$APEX" "prod.$APEX" "dev.$APEX"; do
    BUCKET="${prefix//./-}"
    URL="https://$BUCKET.s3.amazonaws.com"
    RESP=$(curl -s --max-time 8 "$URL" -w "\n%{http_code}" 2>/dev/null)
    CODE=$(echo "$RESP" | tail -1)
    BODY=$(echo "$RESP" | head -n -1)
    if [ "$CODE" = "200" ]; then
        echo "[LISTABLE] s3://$BUCKET - public listing at $URL" >> "$OUT"
        echo "[LISTABLE] s3://$BUCKET"
        echo "$BODY" | grep -oE '<Key>[^<]+' | sed 's/<Key>//' | head -5 | sed 's/^/    /' >> "$OUT"
    elif [ "$CODE" = "403" ]; then
        if echo "$BODY" | grep -qiE "AllAccessDisabled|AccessDenied" && ! echo "$BODY" | grep -qi "no such bucket"; then
            echo "[EXISTS-403] s3://$BUCKET exists but is private (may allow unauthenticated object access if signed URLs leak)" >> "$OUT"
        fi
    fi
done

echo "[*] Checking Azure Blob storage..."
for prefix in "$APEX" "assets" "media" "static" "backup" "files"; do
    BUCKET="${prefix//./}"
    URL="https://$BUCKET.blob.core.windows.net/?restype=container&comp=list"
    CODE=$(curl -s -o "$TMP/azure_$$.xml" -w "%{http_code}" --max-time 8 "$URL" 2>/dev/null)
    if [ "$CODE" = "200" ] && grep -qi "<Blobs\|<Blob>" "$TMP/azure_$$.xml" 2>/dev/null; then
        echo "[LISTABLE] Azure blob: $URL" >> "$OUT"
        echo "[LISTABLE] Azure blob: $URL"
    fi
    rm -f "$TMP/azure_$$.xml"
done

echo "[*] Checking GCS buckets..."
for bucket in "$APEX-uploads" "$APEX-backup" "$APEX-static" "$APEX-media" "$APEX-files" "$APEX-data"; do
    URL="https://storage.googleapis.com/$bucket/?prefix=&max-keys=10"
    CODE=$(curl -s -o "$TMP/gcs_$$.xml" -w "%{http_code}" --max-time 8 "$URL" 2>/dev/null)
    if [ "$CODE" = "200" ] && grep -q "<Key\|<Contents>" "$TMP/gcs_$$.xml" 2>/dev/null; then
        echo "[LISTABLE] gs://$bucket - $URL" >> "$OUT"
        echo "[LISTABLE] gs://$bucket"
        grep -oE '<Name>[^<]+' "$TMP/gcs_$$.xml" | sed 's/<Name>//' | head -5 | sed 's/^/    /' >> "$OUT"
    fi
    rm -f "$TMP/gcs_$$.xml"
done

echo "================================================================" >> "$OUT"
echo "EXPOSED VCS / BACKUP / ENV FILE CHECK (git/sec exposure)" >> "$OUT"
echo "================================================================" >> "$OUT"
GIT_OUT="gitrecon.txt"
> "$GIT_OUT"

PATHS=(
    ".git/config" ".git/HEAD" ".env" ".env.bak" ".svn/entries" ".htaccess"
    "web.config.bak" "backup.sql" "db.sql" "dump.sql" "wp-config.php.bak"
    "config.php.bak" "config.json" ".DS_Store" "backup.zip" "backup.tar.gz"
    "phpinfo.php" "README.md"
)

while IFS= read -r target; do
    target=$(echo "$target" | tr -d '[:space:]')
    [ -z "$target" ] && continue
    BASE="https://$target"
    echo "[*] $BASE" >> "$GIT_OUT"
    for p in "${PATHS[@]}"; do
        CODE=$(curl -sk -o "$TMP/git_resp_$$.txt" -w "%{http_code}" --max-time 8 "$BASE/$p" 2>/dev/null)
        if [ "$CODE" = "200" ] && [ "$(wc -c < "$TMP/git_resp_$$.txt")" -gt 0 ]; then
            echo "[OK] $BASE/$p (200, $(wc -c < "$TMP/git_resp_$$.txt")B)" >> "$GIT_OUT"
            echo "[OK] $BASE/$p"
            if echo "$p" | grep -qiE "\.git/config|\.env$|password|secret|database|db_"; then
                grep -aiE "password|user|db_|secret|key|token|ref:" "$TMP/git_resp_$$.txt" | head -5 | sed 's/^/    /' >> "$GIT_OUT"
            fi
        fi
        rm -f "$TMP/git_resp_$$.txt"
    done
done < "$INPUT"

echo "  (gitrecon.txt = exposed-file findings; manually verify SPA 200 fallbacks)" >> "$OUT"

echo "================================================================" >> "$OUT"
echo "GRAPHQL ENDPOINT / INTROSPECTION CHECK" >> "$OUT"
echo "================================================================" >> "$OUT"
GQL_OUT="graphql_report.txt"
> "$GQL_OUT"

GQL_PATHS=("graphql" "api/graphql" "v1/graphql" "v2/graphql" "graphiql" "graph" "query" "gql" "api/gql")
INTRO_QUERY='{"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"}'

while IFS= read -r target; do
    target=$(echo "$target" | tr -d '[:space:]')
    [ -z "$target" ] && continue
    for base in "https://$target" "http://$target"; do
        for p in "${GQL_PATHS[@]}"; do
            URL="$base/$p"
            STATUS=$(curl -sk -o "$TMP/gql_resp_$$.json" -w "%{http_code}" --max-time 10 \
                -H 'Content-Type: application/json' -d "$INTRO_QUERY" "$URL" 2>/dev/null)
            if [ "$STATUS" = "200" ] && grep -qiE '__schema|queryType|mutationType|"data"' "$TMP/gql_resp_$$.json" 2>/dev/null; then
                echo "[FOUND] $URL (introspection enabled - info disclosure/IDOR)" >> "$GQL_OUT"
                echo "[FOUND] $URL"
            elif [ "$STATUS" = "200" ]; then
                echo "[FOUND] $URL (responds 200 - likely GraphQL/API endpoint)" >> "$GQL_OUT"
            fi
            rm -f "$TMP/gql_resp_$$.json"
        done
    done
done < "$INPUT"

echo "  (gitrecon.txt + graphql_report.txt written)" >> "$OUT"
echo "[+] Done. Misc-bug findings: cloudreport.txt, gitrecon.txt, graphql_report.txt"

{
    echo ""
    echo "========================================================================="
    echo " [dscloudpermissions] MISC ASSET CHECKS $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================================================="
    for rep in cloudreport.txt gitrecon.txt graphql_report.txt; do
        if [ -s "$rep" ]; then
            echo "--- $rep : $(wc -l < "$rep" | tr -d ' ') lines ---"
            cat "$rep"
            echo ""
        fi
    done
} >> fullreport.txt 2>/dev/null

rm -rf "$TMP"
