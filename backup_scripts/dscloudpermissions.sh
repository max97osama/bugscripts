#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <subdomains.txt|domain>"
    echo "  Detects exposed/misconfigured cloud storage (S3, Azure Blob, GCS)."
    echo "  Only tests buckets derived from the target's own domains."
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

echo "[+] Done. Cloud storage findings in $OUT: $(wc -l < "$OUT") lines."

rm -rf "$TMP"
