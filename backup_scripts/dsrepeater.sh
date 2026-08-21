#!/bin/bash

if [ -z "$1" ]; then
    exit 1
fi

TARGET_URL="$1"
REQ_FILE=$(mktemp)

echo "GET / HTTP/1.1" > "$REQ_FILE"
echo "Host: $(echo "$TARGET_URL" | awk -F/ '{print $3}')" >> "$REQ_FILE"
echo "User-Agent: HTTPie" >> "$REQ_FILE"
echo "Accept: */*" >> "$REQ_FILE"
echo "Connection: close" >> "$REQ_FILE"
echo "" >> "$REQ_FILE"

vim "$REQ_FILE"

clear
echo "=== SENT REQUEST ==="
cat "$REQ_FILE"
echo -e "\n=== RECEIVED RESPONSE ==="

METHOD=$(awk 'NR==1 {print $1}' "$REQ_FILE")
HEADERS_ARGS=()

while IFS= read -r line; do
    line=$(echo "$line" | tr -d '\r')
    if [ -z "$line" ]; then
        break
    fi
    if [[ "$line" != *"HTTP/1."* ]]; then
        HEADERS_ARGS+=("$line")
    fi
done < <(tail -n +1 "$REQ_FILE")

BODY_DATA=$(awk 'BEGIN{RS="";ORS="\n\n"}NR>1' "$REQ_FILE")

if [ -n "$BODY_DATA" ] && [ "$METHOD" != "GET" ]; then
    echo "$BODY_DATA" | http --all "$METHOD" "$TARGET_URL" "${HEADERS_ARGS[@]}"
else
    http --all "$METHOD" "$TARGET_URL" "${HEADERS_ARGS[@]}"
fi

rm -f "$REQ_FILE"