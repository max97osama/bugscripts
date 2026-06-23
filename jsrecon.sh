#!/bin/bash

INPUT="${1:-js.txt}"
ALLJS="alljs.txt"
FINDINGS="Findings.txt"

> "$ALLJS"
> "$FINDINGS"

PATTERN='(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|secret|password|passwd|pwd|access[_-]?key|access[_-]?token|auth[_-]?token|authorization|bearer|client[_-]?secret|private[_-]?key|aws_access_key_id|aws_secret_access_key|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|firebase|mongodb\+srv|x-api-key)'

while IFS= read -r url; do
    [ -z "$url" ] && continue

    CONTENT=$(curl -s "$url")
    echo "$CONTENT" >> "$ALLJS"

    echo "$CONTENT" | grep -inE "$PATTERN" | while IFS= read -r line; do
        echo "URL: $url" >> "$FINDINGS"
        echo "$line" >> "$FINDINGS"
        echo "" >> "$FINDINGS"
    done
done < "$INPUT"
