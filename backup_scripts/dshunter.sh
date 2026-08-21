#!/bin/bash

usage() {
    echo "Usage: $0 -d <domain> -l <subdomain_list> -o <output_file>"
    exit 1
}

while getopts ":d:l:o:" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        l) SUBLIST="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        *) usage ;;
    esac
done

if [[ -z "$DOMAIN" || -z "$SUBLIST" || -z "$OUTPUT" ]]; then
    usage
fi

if ! command -v nuclei >/dev/null 2>&1; then
    echo "[-] nuclei not found on PATH. Install it before running hunter.sh"
    exit 1
fi

nuclei -update-templates -silent

trap 'echo "Interrupted, exiting."; exit 130' INT

nuclei -list "$SUBLIST" \
    -tags exposure,vulnerability,default-login,cve,misconfig,takeover,tech \
    -severity critical,high,medium,low \
    -c 2 \
    -bs 2 \
    -rl 15 \
    -timeout 10 \
    -stats \
    -o "$OUTPUT" \
    -etags headless \
    -mhe 1 \
    -ni \
    2>> nuclei_errors.log

if [ $? -eq 0 ]; then
    echo "Done: $OUTPUT"
else
    echo "Error: Check nuclei_errors.log"
fi
