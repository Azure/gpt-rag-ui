#!/usr/bin/env bash
# -------------------------------------------------------------------------
# deploy.sh — validate APP_CONFIG_ENDPOINT, load App Config (label=gpt-rag), then build & push
# -------------------------------------------------------------------------

set -euo pipefail

# Toggle DEBUG for verbose output
DEBUG=${DEBUG:-false}
if [[ "$DEBUG" == "true" ]]; then
  set -x
fi

# colors
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m' # no color

echo
# Early Docker pre-flight check
if command -v docker &>/dev/null; then
  echo -e "${BLUE}🔍 Checking Docker availability…${NC}"
  probeOutput="$(docker info 2>&1 || true)"
  if echo "${probeOutput}" | grep -qiE '(Cannot connect to the Docker daemon|Is the docker daemon running|error during connect|Docker Desktop is manually paused|context deadline exceeded)'; then
    if echo "${probeOutput}" | grep -qi 'manually paused'; then
      echo -e "${YELLOW}❌ Docker Desktop is manually paused. Unpause it via the Whale menu or Dashboard.${NC}"
    else
      echo -e "${YELLOW}❌ Docker Desktop is not running.${NC}"
    fi
    echo -e "${YELLOW}⚠️  Please start/unpause Docker Desktop and re-run this script.${NC}"
    exit 1
  fi
  echo -e "${GREEN}✅ Docker is available.${NC}"
else
  echo -e "${YELLOW}⚠️  Docker CLI not found. Will fall back to 'az acr build'.${NC}"
fi
echo

# First, check shell environment
if [[ -n "${APP_CONFIG_ENDPOINT:-}" ]]; then
  echo -e "${GREEN}✅ Using APP_CONFIG_ENDPOINT from environment: ${APP_CONFIG_ENDPOINT}${NC}"
else
  echo -e "${BLUE}🔍 Fetching APP_CONFIG_ENDPOINT from azd env…${NC}"
  envValues="$(azd env get-values 2>/dev/null || true)"
  APP_CONFIG_ENDPOINT="$(echo "$envValues" \
    | grep -i '^APP_CONFIG_ENDPOINT=' \
    | cut -d '=' -f2- \
    | tr -d '"' \
    | tr -d '[:space:]' || true)"
fi

if [[ -z "${APP_CONFIG_ENDPOINT:-}" ]]; then
  echo -e "${YELLOW}⚠️  Missing APP_CONFIG_ENDPOINT.${NC}"
  echo -e "  • ${BLUE}Set it with:${NC} azd env set APP_CONFIG_ENDPOINT <your-endpoint>"
  echo -e "  • ${BLUE}Or export in shell:${NC} export APP_CONFIG_ENDPOINT=<your-endpoint> before running this script."
  exit 1
fi

echo -e "${GREEN}✅ APP_CONFIG_ENDPOINT: ${APP_CONFIG_ENDPOINT}${NC}"
echo

# derive App Configuration name from endpoint
configName="${APP_CONFIG_ENDPOINT#https://}"
configName="${configName%.azconfig.io}"
if [[ -z "$configName" ]]; then
  echo -e "${YELLOW}⚠️  Could not parse config name from endpoint '${APP_CONFIG_ENDPOINT}'.${NC}"
  exit 1
fi
echo -e "${GREEN}✅ App Configuration name: ${configName}${NC}"
echo

echo -e "${BLUE}🔐 Checking Azure CLI login and subscription…${NC}"
if ! az account show >/dev/null 2>&1; then
  echo -e "${YELLOW}⚠️  Not logged in. Please run 'az login'.${NC}"
  exit 1
fi
echo -e "${GREEN}✅ Azure CLI is logged in.${NC}"
echo

# label for your configuration keys
label="gpt-rag"

echo -e "${GREEN}⚙️ Loading App Configuration settings (label=${label})…${NC}"
echo

# helper to fetch a key (with label) from App Configuration via az CLI
_fetch_config_key() {
  local key="$1"
  local val
  val="$(az appconfig kv show \
    --name "$configName" \
    --key "$key" \
    --label "$label" \
    --auth-mode login \
    --query value -o tsv 2>&1)" || true
  if [[ -z "${val// /}" ]]; then
    return 1
  fi
  echo "$val"
}

get_config_value() {
  local key="$1"
  echo -e "${BLUE}🛠️  Retrieving '$key' (label=${label}) from App Configuration…${NC}" >&2
  local val
  if val="$(_fetch_config_key "$key")" && [[ -n "${val// /}" ]]; then
    echo "$val"
    return 0
  fi
  # uppercase fallback
  local upperKey
  upperKey="$(echo "$key" | tr '[:lower:]' '[:upper:]')"
  if [[ "$upperKey" != "$key" ]]; then
    echo -e "${BLUE}🔍 Trying uppercase key '${upperKey}'…${NC}" >&2
    if val="$(_fetch_config_key "$upperKey")" && [[ -n "${val// /}" ]]; then
      echo "$val"
      return 0
    fi
  fi
  echo -e "${YELLOW}⚠️  Failed to retrieve key '$key'.${NC}" >&2
  return 1
}

# fetch required settings
containerRegistryName=""
containerRegistryLoginServer=""
subscriptionId=""
resourceGroupName=""
resourceToken=""
frontendApp=""
missing_keys=()

if ! containerRegistryName="$(get_config_value "CONTAINER_REGISTRY_NAME")"; then
  missing_keys+=("CONTAINER_REGISTRY_NAME")
fi
if ! containerRegistryLoginServer="$(get_config_value "CONTAINER_REGISTRY_LOGIN_SERVER")"; then
  missing_keys+=("CONTAINER_REGISTRY_LOGIN_SERVER")
fi
if ! subscriptionId="$(get_config_value "SUBSCRIPTION_ID")"; then
  missing_keys+=("SUBSCRIPTION_ID")
fi
if ! resourceGroupName="$(get_config_value "AZURE_RESOURCE_GROUP")"; then
  missing_keys+=("AZURE_RESOURCE_GROUP")
fi
if ! resourceToken="$(get_config_value "RESOURCE_TOKEN")"; then
  missing_keys+=("RESOURCE_TOKEN")
fi
if ! frontendApp="$(get_config_value "FRONTEND_APP_NAME")"; then
  missing_keys+=("FRONTEND_APP_NAME")
fi

if [[ ${#missing_keys[@]} -gt 0 ]]; then
  echo -e "${YELLOW}⚠️  Missing or invalid App Config keys: ${missing_keys[*]}${NC}"
  exit 1
fi

echo -e "${GREEN}✅ All App Configuration values retrieved:${NC}"
echo "   containerRegistryName = $containerRegistryName"
echo "   containerRegistryLoginServer = $containerRegistryLoginServer"
echo "   subscriptionId = $subscriptionId"
echo "   resourceGroupName = $resourceGroupName"
echo "   resourceToken = $resourceToken"
echo "   frontendApp = $frontendApp"
echo

echo -e "${GREEN}🔐 Logging into ACR (${containerRegistryName} in ${resourceGroupName})…${NC}"
az acr login --name "${containerRegistryName}" --resource-group "${resourceGroupName}"
echo -e "${GREEN}✅ Logged into ACR.${NC}"
echo

echo -e "${BLUE}🛢️ Defining tag…${NC}"
if [[ -n "${tag:-}" ]]; then
    # Use existing environment variable
    tag="${tag}"
    echo -e "${GREEN}Using tag from environment: ${tag}${NC}"
else
    # Try Git short HEAD
    if gitShort=$(git rev-parse --short HEAD 2>/dev/null); then
        if [[ -n "$gitShort" ]]; then
            tag="$gitShort"
            echo -e "${GREEN}Using Git short HEAD as tag: ${tag}${NC}"
        else
            echo -e "${YELLOW}Could not get Git short HEAD. Generating random tag.${NC}"
            # Generate random 8-digit number between 100000 and 999999
            rand=$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
            rand=$(( rand % 900000 + 100000 ))
            tag="GPT${rand}"
            echo -e "${GREEN}Generated random tag: ${tag}${NC}"
        fi
    else
        echo -e "${YELLOW}Git command failed. Generating random tag.${NC}"
        # Generate random 8-digit number between 100000 and 999999
        rand=$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
        rand=$(( rand % 900000 + 100000 ))
        tag="GPT${rand}"
        echo -e "${GREEN}Generated random tag: ${tag}${NC}"
    fi
fi

fullImageName="${containerRegistryLoginServer}/azure-gpt-rag/frontend:${tag}"

if command -v docker &>/dev/null; then
  echo -e "${GREEN}🛠️  Building Docker image…${NC}"
  docker build \
    --platform linux/amd64 \
    -t "${fullImageName}" \
    .

  echo
  echo -e "${GREEN}📤 Pushing image…${NC}"
  docker push "${fullImageName}"
  echo -e "${GREEN}✅ Image pushed.${NC}"
else
  echo -e "${BLUE}⚠️  Docker CLI not found locally. Falling back to 'az acr build'.${NC}"
  az acr build \
    --registry "${containerRegistryName}" \
    --image "azure-gpt-rag/frontend:${tag}" \
    --file Dockerfile \
    .
  echo -e "${GREEN}✅ ACR cloud build succeeded. Image is already in ACR — no local push needed.${NC}"
fi

echo
echo -e "${GREEN}🔄 Updating container app registry authentication…${NC}"
identityType="$(az containerapp identity show \
  --name "${frontendApp}" \
  --resource-group "${resourceGroupName}" \
  --query type -o tsv 2>/dev/null || true)"

if echo "${identityType}" | grep -qi "UserAssigned"; then
  az containerapp registry set \
    --name "${frontendApp}" \
    --resource-group "${resourceGroupName}" \
    --server "${containerRegistryName}.azurecr.io" \
    --identity "/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uai-ca-${resourceToken}-frontend"
else
  az containerapp registry set \
    --name "${frontendApp}" \
    --resource-group "${resourceGroupName}" \
    --server "${containerRegistryName}.azurecr.io" \
    --identity "system"
fi
echo -e "${GREEN}✅ Container app registry updated.${NC}"

echo
echo -e "${GREEN}🔄 Updating container app…${NC}"
az containerapp update \
  --name "${frontendApp}" \
  --resource-group "${resourceGroupName}" \
  --image "${fullImageName}"
echo -e "${GREEN}✅ Container app updated.${NC}"

echo
echo -e "${BLUE}🔍 Fetching current revision…${NC}"
currentRevision="$(az containerapp revision list \
  --name "${frontendApp}" \
  --resource-group "${resourceGroupName}" \
  --query "[0].name" -o tsv)"

echo -e "${GREEN}🔄 Restarting container app revision (${currentRevision})…${NC}"
az containerapp revision restart \
  --name "${frontendApp}" \
  --resource-group "${resourceGroupName}" \
  --revision "${currentRevision}"
echo -e "${GREEN}✅ Container app revision restarted.${NC}"
