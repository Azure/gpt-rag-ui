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

To run the application locally, you must define the required environment variables using a `.env` file or by exporting them directly to your local environment.  
You can use the provided `.env.template` as a starting point:

```bash
cp .env.template .env
```

For cloud deployments on **Azure App Service**, this repository also provides a ready-to-use `app_settings.json` file containing all the recommended environment variables, already formatted for direct use.  
You can simply copy its content and paste it into **Azure Portal > App Service > Configuration > Application settings > Advanced Edit**.

#### ✅ **Required Variables**

| Variable | Description |
|---------|-------------|
| `ORCHESTRATOR_STREAM_ENDPOINT` | URL of the orchestrator's `/api/orcstream` endpoint |
| `AZURE_SUBSCRIPTION_ID` | Your Azure subscription ID where Orchestrator Function App is deployed |
| `AZURE_RESOURCE_GROUP_NAME` | Resource group where Orchestrator Function App is deployed |
| `AZURE_ORCHESTRATOR_FUNC_NAME` | Name of the orchestrator Function App |
| `STORAGE_ACCOUNT` | Storage account where source documents are located |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Connection string for Azure Application Insights to enable telemetry and monitoring for the application. Use the connection string provided by your Application Insights resource. |

#### 🔐 **Optional: Entra ID Authentication (Azure AD)**

To enable user authentication via Microsoft Entra ID (formerly Azure AD), set `ENABLE_AUTHENTICATION=true` and define:

| Variable | Description |
|---------|-------------|
| `ENABLE_AUTHENTICATION` | Set to `true` to require login (default: `false`) |
| `CHAINLIT_SECRET_KEY` | Secret used for session security in Chainlit |
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

Perfeito! Aqui está a versão ajustada e mais direta, orientando a pessoa a usar exatamente essas variáveis como estão:

### ⚙ **Platform Required Variables (Azure App Service Variables)**

When deploying to **Azure App Service**, make sure to configure the following variables exactly as shown below. These variables are required to ensure proper build, deployment, and observability.

| Variable | Description |
|----------|-------------|
| `BUILD_FLAGS` | Must be set to `UseExpressBuild` to enable express build mode. |
| `ENABLE_ORYX_BUILD` | Must be set to `True` to enable the Oryx build system. |
| `SCM_DO_BUILD_DURING_DEPLOYMENT` | Must be set to `True` to allow the App Service to build the application during deployment. |
| `WEBSITE_HTTPLOGGING_RETENTION_DAYS` | Set the number of days to retain HTTP logs. Recommended value is `1`. |
| `XDG_CACHE_HOME` | Defines the cache directory used during build and runtime. Recommended value is `/tmp/.cache`. |

> ✅ **Recommendation**: For consistency and to avoid deployment issues, use these exact values unless you have a strong reason to customize them.

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
  --role "Website Contributor" \
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

