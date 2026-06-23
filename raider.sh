
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Aider VM Control Script${NC}"
echo "================================"

if [ -z "$DEEPSEEK_API_KEY" ]; then
    echo -e "${YELLOW}DeepSeek API key not found in environment${NC}"
    read -p "Enter your DeepSeek API key: " api_key
    export DEEPSEEK_API_KEY="$api_key"
fi


aider \
  --model "deepseek/deepseek-chat" \
 --api-key "deepseek=${DEEPSEEK_API_KEY}" \
 --dark-mode \
  --yes-always \
  --no-auto-commits \
  --no-git \
  --no-show-release-notes \
  --map-refresh auto \
  --architect \
  --editor vim \
  --pretty \
  --stream \
  "$@"
