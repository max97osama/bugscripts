#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <subdomains.txt|domain>"
    echo "  Probes common GraphQL endpoints, dumps introspection schema,"
    echo "  flags introspection-enabled / IDOR-prone instances."
    exit 1
fi

INPUT="$1"
OUT="graphql_report.txt"
> "$OUT"

TMP="/tmp/graphql_$$"
mkdir -p "$TMP"

TARGETS="$TMP/targets.txt"
> "$TARGETS"

if [ -f "$INPUT" ]; then
    grep -vE '^\s*$' "$INPUT" | sort -u > "$TARGETS"
else
    echo "$INPUT" > "$TARGETS"
fi

GQL_PATHS=("graphql" "api/graphql" "v1/graphql" "v2/graphql" "graphiql" "graph" "query" "gql" "api/gql")

INTRO_QUERY='{"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"}'

echo "======================================================================" >> "$OUT"
echo "GRAPHQL RECON REPORT - $(date)" >> "$OUT"
echo "======================================================================" >> "$OUT"

while IFS= read -r target; do
    target=$(echo "$target" | tr -d '[:space:]')
    [ -z "$target" ] && continue

    for base in "https://$target" "http://$target"; do
        for p in "${GQL_PATHS[@]}"; do
            URL="$base/$p"
            STATUS=$(curl -sk -o "$TMP/resp_$$.json" -w "%{http_code}" --max-time 10 \
                "$URL" -H 'Content-Type: application/json' \
                -d "$INTRO_QUERY" 2>/dev/null)

            if [ "$STATUS" = "200" ] && grep -qiE '__schema|queryType|mutationType|types|"data"' "$TMP/resp_$$.json" 2>/dev/null; then
                echo "[FOUND] $URL (introspection enabled - potential info disclosure/IDOR)" >> "$OUT"
                echo "[FOUND] $URL"
                echo "  Schema name: $(grep -oE '"name":"[^"]*"' "$TMP/resp_$$.json" 2>/dev/null | head -3 | tr '\n' ' ')" >> "$OUT"
            elif [ "$STATUS" = "200" ]; then
                echo "[FOUND] $URL (responds 200 - likely GraphQL or API endpoint)" >> "$OUT"
            fi
            rm -f "$TMP/resp_$$.json"
        done
    done
done < "$TARGETS"

echo "[+] Done. GraphQL findings in $OUT: $(wc -l < "$OUT") lines."

rm -rf "$TMP"
