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

rm -f "$TEMP1" "$TEMP2"
