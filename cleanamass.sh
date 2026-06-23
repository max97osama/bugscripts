#!/bin/bash

if [ -z "$1" ]; then
    exit 1
fi

TARGET="$1"

amass enum -d "$TARGET" | grep -E "^[a-zA-Z0-9.-]+\.$TARGET" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[mGK]//g" | sort -u > amassoutput.txt