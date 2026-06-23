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

							nuclei -update-templates -silent

							trap 'exit' INT

							nuclei -l "$SUBLIST" \
								    -tags exposure,vulnerability,default-login,cve,misconfig,takeover,tech \
								        -severity critical,high,medium,low \
									    -c 2 \
									        -bs 2 \
										    -rl 10 \
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
