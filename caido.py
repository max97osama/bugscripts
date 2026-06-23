#!/usr/bin/env python3
import sys
import os
import subprocess
import requests

if len(sys.argv) < 2:
    sys.exit(1)

target_url = sys.argv[1]
caido_api = "http://127.0.0.1:8080/graphql"

# 1. Generate a template raw HTTP request
template = (
    f"GET {target_url} HTTP/1.1\r\n"
    f"User-Agent: Caido-Terminal\r\n"
    f"Accept: */*\r\n"
    f"Connection: close\r\n\r\n"
)

# 2. Open Vim to let you edit the raw request interactively
tmp_file = "/tmp/caido_req.txt"
with open(tmp_file, "w") as f:
    f.write(template)

subprocess.call(["vim", tmp_file])

with open(tmp_file, "r") as f:
    raw_request = f.read()

os.remove(tmp_file)

# 3. Format the GraphQL mutation payload for Caido
graphql_query = {
    "query": """
    mutation SendRawRequest($raw: String!) {
        sendRequest(input: { raw: $raw }) {
            request {
                raw
            }
            response {
                raw
            }
        }
    }
    """,
    "variables": {
        "raw": raw_request
    }
}

# 4. Send it to the Caido backend daemon
try:
    res = requests.post(caido_api, json=graphql_query)
    data = res.json()
    
    # Extract the response payload from Caido's backend
    errors = data.get("errors")
    if errors:
        print(f"Caido Error: {errors}")
        sys.exit(1)
        
    response_raw = data["data"]["sendRequest"]["response"]["raw"]
    
    print("=== SENT REQUEST ===")
    print(raw_request)
    print("\n=== RECEIVED RESPONSE FROM CAIDO ===")
    print(response_raw)

except Exception as e:
    print(f"Could not connect to caido-cli daemon: {e}")