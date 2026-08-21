#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

TARGET="$1"
OUTPUT="${2:-amassoutput.txt}"

amass enum -passive -d "$TARGET" 2>/dev/null \
    | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[mGK]//g" \
    | grep -E "^[a-zA-Z0-9.-]+\.$TARGET$" \
    | tr '[:upper:]' '[:lower:]' \
    | sort -u > "$OUTPUT"

echo "[+] Passive subdomains for $TARGET: $(wc -l < "$OUTPUT")"
