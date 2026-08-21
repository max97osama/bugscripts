#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <urls.txt> [target_domain]"
    exit 1
fi

if command -v dsurlfilter >/dev/null 2>&1; then
    dsurlfilter "$@"
    exit $?
fi

echo "[-] dsurlfilter not found on PATH; nothing to do."
exit 1
