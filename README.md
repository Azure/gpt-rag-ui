# Enterprise RAG Web UI

Part of the [GPT-RAG](https://github.com/Azure/gpt-rag) solution.

This project provides a user interface built with [Chainlit](https://www.chainlit.io/) to interact with GPT-powered retrieval-augmented generation systems. It is designed to work seamlessly with the Orchestrator backend and supports customization and theming.

---

## 🚀 Quickstart – Run Locally

### **Pre-requisites**

- Python 3.11+
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)

---

### **1. Setup Environment and Install Dependencies**

```bash
python -m venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

### 🔧 **2. Environment Variable Configuration**

Before running the application, define required variables in a `.env` file or export them to your environment.

You can copy the `.env.template` as a starting point:

```bash
cp .env.template .env
```

#### ✅ **Required Variables**

| Variable | Description |
|---------|-------------|
| `ORCHESTRATOR_STREAM_ENDPOINT` | URL of the orchestrator's `/api/orcstream` endpoint |
| `AZURE_SUBSCRIPTION_ID` | Your Azure subscription ID |
| `AZURE_RESOURCE_GROUP_NAME` | Resource group where your Function App is deployed |
| `AZURE_ORCHESTRATOR_FUNC_NAME` | Name of the orchestrator Function App |
| `BLOB_STORAGE_ACCOUNT_NAME` | Storage account where source documents are located |
| `BLOB_STORAGE_CONTAINER` | Container within the storage account |
| `CHAINLIT_SECRET_KEY` | Secret used for session security in Chainlit |

#### 🔐 **Optional: Entra ID Authentication (Azure AD)**

To enable user authentication via Microsoft Entra ID (formerly Azure AD), set `ENABLE_AUTHENTICATION=true` and define:

| Variable | Description |
|---------|-------------|
| `ENABLE_AUTHENTICATION` | Set to `true` to require login (default: `false`) |
| `OAUTH_AZURE_AD_CLIENT_ID` | App registration's Client ID |
| `OAUTH_AZURE_AD_CLIENT_SECRET` | App registration's secret |
| `OAUTH_AZURE_AD_TENANT_ID` | Entra tenant ID (directory ID) |
| `OAUTH_AZURE_AD_ENABLE_SINGLE_TENANT` | Set to `true` if app is single-tenant |
| `OAUTH_AZURE_AD_SCOPES` | *(Optional)* Comma-separated scopes used to request an access token for API calls. The access token can be used to call protected APIs such as Microsoft Graph or Power BI REST API. Default is `User.Read`. To access Power BI, for example, add `https://analysis.windows.net/powerbi/api/.default` |


#### 🎯 **Optional: Authorization Filters**

To restrict access to specific users or groups, use:

| Variable | Description |
|----------|-------------|
| `ALLOWED_USER_NAMES` | Comma-separated list of allowed usernames |
| `ALLOWED_USER_PRINCIPALS` | Comma-separated list of allowed object IDs |
| `ALLOWED_GROUP_NAMES` | Comma-separated list of allowed group names |

---

### **3. Run the Application Locally**

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

---

## ☁️ Deploy to Azure

### **Option 1: Azure App Service (via VS Code or Portal)**

Use the App Service extension to deploy the code. Then configure the **Startup Command**:

```bash
python -m uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
```

### **Option 2: Azure CLI**

#### Zip the source code

```bash
rm -f deploy.zip && zip -r deploy.zip *  # Linux/macOS
# or
Remove-Item -Force deploy.zip; tar -a -c -f deploy.zip *  # Windows PowerShell
```

#### Deploy it

```bash
az webapp deploy \
  --subscription <SUBSCRIPTION_ID> \
  --resource-group <RESOURCE_GROUP_NAME> \
  --name <WEB_APP_NAME> \
  --src-path deploy.zip \
  --type zip \
  --async true
```

---

## 🔐 Required Permissions

Ensure the user/service principal running the UI has these roles:

### Function App

```bash
az role assignment create \
  --assignee <principalId> \
  --role "Contributor" \
  --scope "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroup>/providers/Microsoft.Web/sites/<functionAppName>"
```

### Storage Account

```bash
az role assignment create \
  --assignee <principalId> \
  --role "Storage Blob Data Reader" \
  --scope "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroup>/providers/Microsoft.Storage/storageAccounts/<storageAccount>"
```

---

## 🎨 Customization

- Modify theme in `public/theme.json`
- Customize layout with `public/custom.css`
- Adjust app behavior in `.chainlit/config.toml`

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](https://github.com/Azure/GPT-RAG/blob/main/CONTRIBUTING.md) for guidelines.

