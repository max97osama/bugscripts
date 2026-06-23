#!/bin/bash

if [ "$#" -lt 3 ]; then
	    echo "Usage: $0 <domain|domains.txt> <depth> <wordlist.txt>"
	        exit 1
fi
INPUT="$1"
DEPTH="$2"
WORDLIST="$3"

CRAWL_OUT="curls.txt"
URLS_FILE="urls.txt"

touch "$CRAWL_OUT" "$URLS_FILE"

TARGETS="/tmp/crawl_targets_$$.txt"
> "$TARGETS"

if [ -f "$INPUT" ]; then
	    while IFS= read -r line; do
		            line=$(echo "$line" | tr -d '[:space:]')
			            [ -z "$line" ] && continue
				            if echo "$line" | grep -qE "^https?://"; then
						                echo "$line" >> "$TARGETS"
								        else
										            echo "https://$line" >> "$TARGETS"
											            fi
												        done < "$INPUT"
												else
													    if echo "$INPUT" | grep -qE "^https?://"; then
														            echo "$INPUT" >> "$TARGETS"
															        else
																	        echo "https://$INPUT" >> "$TARGETS"
																		    fi
fi

sort -u "$TARGETS" -o "$TARGETS"

echo "[*] Total targets: $(wc -l < "$TARGETS")"

RAW_ALL="/tmp/crawl_raw_$$.txt"
> "$RAW_ALL"


