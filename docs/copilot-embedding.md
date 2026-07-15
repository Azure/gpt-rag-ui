# Embed GPT-RAG with Chainlit Copilot

Chainlit Copilot can embed the GPT-RAG chat in an external portal. Embedding is
off by default. When it is off, the standalone UI, authentication, CORS, and
cookie behavior remain unchanged.

## Configure the UI

Add these keys to Azure App Configuration with the `gpt-rag-ui` or `gpt-rag`
label. Container environment variables with the same names take precedence.

| Key | Required | Description |
| --- | --- | --- |
| `CHAINLIT_COPILOT_ENABLED` | Yes | Set to `true` to enable embedding. The default is `false`. |
| `CHAINLIT_ALLOWED_ORIGINS` | Yes when enabled | Comma-separated portal origins, for example `https://portal.contoso.com`. Wildcards, URL paths, credentials, the `null` origin, and non-local HTTP origins are rejected. |
| `CHAINLIT_COPILOT_AUTH_MODE` | No | `anonymous` (default) or `entra`. The selected policy applies to both the embedded and standalone clients on this deployment. |
| `CHAINLIT_COOKIE_SAMESITE` | No | `lax` (default), `strict`, or `none`. Use `none` only for a cross-site HTTPS portal. |
| `CHAINLIT_COPILOT_ENTRA_TENANT_ID` | Entra mode | Tenant GUID whose v2.0 access tokens are accepted. |
| `CHAINLIT_COPILOT_ENTRA_AUDIENCE` | Entra mode | Exact `aud` claim expected in the portal's access token, usually the application ID URI exposed by the API registration. |
| `CHAINLIT_COPILOT_ENTRA_REQUIRED_SCOPE` | No | Delegated scope required in `scp`. Defaults to `user_impersonation`. App-only tokens without this delegated scope are rejected. |

Restart the UI after changing these startup settings. Invalid enabled
configuration fails startup rather than falling back to wildcard CORS or
anonymous access.

### Same-site and cross-site deployments

Prefer serving the portal and chat under the same site, through a subdomain or a
reverse proxy such as Azure Front Door. This avoids dependence on third-party
cookies.

For a separate-site deployment:

- use HTTPS for the portal and the Chainlit server;
- list every portal origin explicitly in `CHAINLIT_ALLOWED_ORIGINS`;
- set `CHAINLIT_COOKIE_SAMESITE=none`;
- test with the target browsers because third-party-cookie policies can still
  block session cookies.

In a Zero Trust GPT-RAG deployment, the UI Container App is not public. Publish
the UI only through the environment's approved front door or gateway. Do not
expose the Container App directly.

## Initialize the portal widget

Chainlit serves the widget bundle from `/copilot/index.js`. Load it only after
the server URL and, for Entra mode, the access token are available. Keep an
operator-visible fallback if the script or token acquisition fails.

```html
<div id="gpt-rag-status" role="status">Loading assistant…</div>
<script>
  async function startGptRagCopilot() {
    const status = document.getElementById("gpt-rag-status");
    const chainlitServer = "https://chat.contoso.com";

    try {
      // In Entra mode, obtain a token for CHAINLIT_COPILOT_ENTRA_AUDIENCE
      // through the portal's existing MSAL flow. Do not put tokens in HTML.
      const accessToken = await portalAuth.getGptRagAccessToken();

      const script = document.createElement("script");
      script.src = `${chainlitServer}/copilot/index.js`;
      script.onload = () => {
        window.mountChainlitWidget({
          chainlitServer,
          accessToken,
          displayMode: "floating",
          theme: "light"
        });
        status.remove();
      };
      script.onerror = () => {
        status.textContent = "The assistant is unavailable.";
      };
      document.body.appendChild(script);
    } catch {
      status.textContent = "Sign in to open the assistant.";
    }
  }

  startGptRagCopilot();
</script>
```

For anonymous mode, omit `accessToken` and the portal token call.

The pinned Chainlit 2.9.4 Copilot sends `accessToken` to `/auth/jwt`. When Entra
mode is enabled, GPT-RAG routes that request to Chainlit header authentication
and validates the token's RS256 signature against the tenant's JWKS, along with
`exp`, exact v2.0 issuer, audience, tenant, the configured delegated scope, and
`oid` or `sub`. The stable user
identifier is `oid`, falling back to `sub`; `preferred_username`, `email`, or
`upn` is used only as the display/principal name. The original access token is
forwarded to the orchestrator. The Chainlit session expires no later than the
Entra token, so a refreshed portal token is required after expiry.

## Security behavior

- Both Chainlit and host endpoints such as `/version-footer` and
  `/api/download` use the explicit origin list while embedding is enabled.
- Responses permit framing only by `'self'` and the configured portal origins
  through CSP `frame-ancestors`. `X-Frame-Options: DENY` is removed only in
  enabled embedding mode.
- Entra mode does not share `CHAINLIT_AUTH_SECRET` with the portal. That secret
  remains internal to Chainlit session cookies.
- Tokens with the wrong signature algorithm, signing key, issuer, audience,
  tenant, delegated scope, lifetime, or subject are rejected.
- HTTP and WebSocket requests with an unlisted cross-origin `Origin` header are
  rejected before Chainlit handles them.
