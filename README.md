<!-- 
page_type: sample
languages:
- azdeveloper
- powershell
- bicep
products:
- azure
- azure-ai-foundry
- azure-openai
- azure-ai-search
urlFragment: GPT-RAG
name: Multi-repo ChatGPT and Enterprise data with Azure OpenAI and AI Search
description: GPT-RAG core is a Retrieval-Augmented Generation pattern running in Azure, using Azure AI Search for retrieval and Azure OpenAI large language models to power ChatGPT-style and Q&A experiences.
-->
# GPT-RAG Web UI

Part of the [GPT-RAG](https://github.com/Azure/gpt-rag) solution.

This repo provides a user interface built with [Chainlit](https://www.chainlit.io/) to interact with GPT-powered retrieval-augmented generation systems. It is designed to work seamlessly with the Orchestrator backend and supports customization and theming.

## Documentation

For comprehensive information about GPT-RAG, including architecture details, configuration guides, best practices, troubleshooting resources, deployment guidance, customization options, and advanced usage scenarios, please refer to the [official project documentation](https://azure.github.io/GPT-RAG/).

The canonical architecture and deployment documentation remains the
[GPT-RAG documentation site](https://azure.github.io/GPT-RAG/). The
repository-specific security contract and portal integration steps for the
opt-in Chainlit Copilot widget are documented in
[Embed GPT-RAG with Chainlit Copilot](docs/copilot-embedding.md).

Chainlit Copilot embedding is opt-in and disabled by default. Enabling the
script/widget requires an explicit `anonymous` or `entra` mode, distinct exact
portal and UI origins, and a private or authenticated network boundary; origin
checks are not authentication. See
[Embed GPT-RAG with Chainlit Copilot](docs/copilot-embedding.md) for
configuration, CSP, deployment, security, rollout, and rollback guidance.

## Prerequisites

Provision the infrastructure first by following the GPT-RAG repository instructions [GPT-RAG](https://github.com/azure/gpt-rag). This ensures all required Azure resources (e.g., Container App, Storage, AI Search) are in place before deploying the web application.

<details markdown="block">
<summary>Click to view <strong>software</strong> prerequisites</summary>
<br>
The machine used to customize and or deploy the service should have:

* Azure CLI: [Install Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli)
* Azure Developer CLI (optional, if using azd): [Install azd](https://learn.microsoft.com/en-us/azure/developer/azure-developer-cli/install-azd)
* Git: [Download Git](https://git-scm.com/downloads)
* Python 3.12: [Download Python 3.12](https://www.python.org/downloads/release/python-3120/)
* Docker CLI: [Install Docker](https://docs.docker.com/get-docker/)
* VS Code (recommended): [Download VS Code](https://code.visualstudio.com/download)
</details>

## Deployment steps

Make sure you're logged in to Azure before anything else:

```bash
az login
```

### Deploying the app with azd (recommended)

Initialize the template:
```shell
azd init -t azure/gpt-rag-ui 
```
> [!IMPORTANT]
> Use the **same environment name** with `azd init` as in the infrastructure deployment to keep components consistent.

Update env variables then deploy:
```shell
azd env refresh
azd deploy 
```
> [!IMPORTANT]
> Run `azd env refresh` with the **same subscription** and **resource group** used in the infrastructure deployment.

### Hosted-agent chat backend

The default `CHAT_BACKEND=orchestrator` behavior is unchanged. To use the
Microsoft Foundry hosted runtime, set these values in Azure App Configuration
with the `gpt-rag` label (or as environment variables for local development):

| Setting | Required | Description |
| --- | --- | --- |
| `CHAT_BACKEND` | Yes | Set to `hosted_agent`. Any other value except `orchestrator` fails startup; there is no backend fallback. |
| `HOSTED_AGENT_BASE_URL` | Yes | HTTPS base URL of the deployed hosted orchestrator. The UI sends `POST /invocations` to this URL. |
| `HOSTED_AGENT_RESOURCE_SCOPE` | Yes | Exact deployed data-plane audience as an Entra scope ending in `/.default`, for example `api://<application-id>/.default`. The Azure Resource Manager scope is rejected. |
| `HOSTED_AGENT_SSE_IDLE_TIMEOUT_SECONDS` | No | Maximum wait for the next SSE data from the hosted runtime. Defaults to 60 seconds and must be finite and positive. |

The UI acquires the data-plane token on the server through managed identity
(Azure CLI is available only in the local credential chain). Tokens and caller
identity fields are never sent by the browser or included in the invocation
payload. The request contains ordered user/assistant messages, optional managed
`conversation_id`, and correlation metadata only.

Because only the hosted runtime can issue a managed `conversation_id`, start a
new hosted conversation with a text message before uploading documents. The UI
rejects first-turn uploads rather than fabricating an ID. A resumed Chainlit
thread restores context from its ordered messages and obtains a fresh managed
ID from the hosted runtime.

Before enabling hosted mode in production, grant the UI managed identity the
hosted runtime's data-plane role and verify token acquisition using the exact
configured audience. Live acceptance still requires Basic and isolated
topology validation, two-turn managed conversation continuity, and a two-user
negative document-authorization test. These deployment and identity checks
cannot be proven by the repository unit tests.

### Deploying the app with a shell script

To deploy using a script, first clone the repository, set the App Configuration endpoint, and then run the deployment script.

##### PowerShell (Windows)

```powershell
git clone https://github.com/Azure/gpt-rag-ui.git
$env:APP_CONFIG_ENDPOINT = "https://<your-app-config-name>.azconfig.io"
cd gpt-rag-ui
.\scripts\deploy.ps1
```

##### Bash (Linux/macOS)
```bash
git clone https://github.com/Azure/gpt-rag-ui.git
export APP_CONFIG_ENDPOINT="https://<your-app-config-name>.azconfig.io"
cd gpt-rag-ui
./scripts/deploy.sh
````

## 🎨 Customization

- Modify theme in `public/theme.json`
- Customize layout with `public/custom.css`
- Adjust app behavior in `.chainlit/config.toml`

### Release footer

The UI can show release versions in a subtle footer at the bottom of the page.

- `SHOW_RELEASE_FOOTER` (boolean, default `true`): enables or disables footer display.
- `RELEASE` (string): GPT-RAG release value from App Configuration.
- `VERSION` file: GPT-RAG UI release value (local file in this repository).

Display format:

`gpt-rag vX.Y.Z | gpt-rag-ui vA.B.C`

Behavior:

- If a value does not start with `v`, the prefix is added automatically.
- If one value is missing, the footer shows an English fallback message for that side.
- The frontend fetches release data from `/version-footer`.

## Found an Issue?

Encountered an error or bug? Help us improve the quality of this accelerator by reporting issues or suggesting enhancements on our [GitHub Issues page](https://github.com/Azure/GPT-RAG/issues). Your feedback helps make GPT-RAG better for everyone!

## Previous Releases

> [!NOTE]  
> For earlier versions, use the corresponding release in the GitHub repository (e.g., v1.0.0 for the initial version).

## 🤝 Contributing

We appreciate contributions! See [CONTRIBUTING](https://github.com/Azure/gpt-rag/blob/main/CONTRIBUTING.md) for guidelines on submitting pull requests.

## Trademarks


This project may contain trademarks or logos. Authorized use of Microsoft trademarks or logos must follow [Microsoft’s Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Modified versions must not imply sponsorship or cause confusion. Third-party trademarks are subject to their own policies.
