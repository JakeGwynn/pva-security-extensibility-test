# Test PVA / Copilot Studio Security Extensibility — All Environments

A small PowerShell utility that calls the **Power Virtual Agents / Copilot Studio
Security Extensibility "test" API** against **every Power Platform environment**
in your tenant.

It is the bulk equivalent of the request the Copilot Studio admin UI sends when
you click **Test** on a security extensibility configuration:

```http
POST https://{envIdHost}.environment.api.powerplatform.com/powervirtualagents/api/securityExtensibility/test?api-version=2022-03-01-preview
Authorization: Bearer <delegated token>
Content-Type: application/json

{
  "endpoint": "https://your-extensibility-endpoint.example.com",
  "appId":    "00000000-0000-0000-0000-000000000000"
}
```

The script:

1. Signs you in with **OAuth2 device code flow** (delegated permissions) against
   an Entra app registration that you provide.
2. Lists every environment via the BAP REST API
   (`https://api.bap.microsoft.com/.../scopes/admin/environments`).
3. Builds the per-environment PVA host (strip dashes from the env id, insert a
   `.` before the last 2 characters, append
   `.environment.api.powerplatform.com`).
4. POSTs the test payload and prints the response (or full HTTP error) for each
   environment.

> Works in **Windows PowerShell 5.1** and **PowerShell 7+**. No external modules
> required — all HTTP calls go through `Invoke-WebRequest`.

---

## Usage

```powershell
.\Invoke-PvaSecurityExtensibilityTestAllEnvironments.ps1 `
    -Endpoint "https://your-extensibility-endpoint.example.com" `
    -AppId    "00000000-0000-0000-0000-000000000000" `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "00000000-0000-0000-0000-000000000000"
```

| Parameter               | Required | Description |
|-------------------------|----------|-------------|
| `-Endpoint`             | yes      | The endpoint URL sent in the request body (the security extensibility endpoint to test). |
| `-AppId`                | yes      | The Entra app id sent in the request body — i.e. the app the extensibility endpoint expects tokens to come from. |
| `-TenantId`             | yes      | Entra tenant id used for sign-in. |
| `-ClientId`             | yes      | Entra app registration used for delegated sign-in (see setup below). |
| `-ApiVersion`           | no       | API version. Defaults to `2022-03-01-preview`. |
| `-EnvironmentNameFilter`| no       | Optional wildcard filter on environment display name. |

On first run you'll see a device-code prompt. Sign in with a Power Platform
admin account; subsequent token acquisition in the same run is silent (refresh
token is reused).

---

## Entra app registration setup

You need a brand-new Entra app registration (or an existing one configured as
described below). The signed-in **user** does the actual work — the app is just
the OAuth client through which the token is acquired.

### 1. Register the app

In the Entra admin center → **Applications → App registrations → New registration**:

- **Name:** `PVA Security Extensibility Test` (any name)
- **Supported account types:** *Accounts in this organizational directory only (single tenant)*
- **Redirect URI:** *(leave blank — device code flow doesn't need one)*

Copy the **Application (client) ID** and **Directory (tenant) ID** — these go
into `-ClientId` and `-TenantId`.

### 2. Allow public client flows

**Authentication** blade → **Advanced settings** → **Allow public client flows = Yes** → **Save**.

This is required for the OAuth2 device code flow.

### 3. Add API permissions (delegated)

**API permissions → Add a permission**. Add the following **delegated** permissions:

| API | Permission | Purpose |
|-----|-----------|---------|
| **Power Platform API** (`https://api.powerplatform.com`) | `PowerVirtualAgents.AdminActions.Invoke` | Call the PVA / Copilot Studio admin endpoints (the `securityExtensibility/test` POST). |
| **Power Platform API** | `CopilotStudio.AdminActions.Invoke` | Newer name for the same family of admin actions; some tenants gate the API on this. |
| **PowerApps Service** (`https://service.powerapps.com`) | `User` | List environments via the BAP API. |
| **Microsoft Graph** | `User.Read` | Sign-in only (default). |

If "Power Platform API" doesn't appear in the picker:

1. Click **APIs my organization uses** and search for **"Power Platform API"**.
2. If it still isn't listed, run this one-time tenant bootstrap (PowerShell, as
   a Global Admin) — it provisions the first-party "Power Platform API"
   service principal in your tenant:
   ```powershell
   Connect-MgGraph -Scopes "Application.ReadWrite.All"
   New-MgServicePrincipal -AppId "8578e004-a5c6-46e7-913e-12f58912df43"
   ```
   Then refresh the **Add a permission** dialog.

### 4. Grant admin consent

**API permissions** → **Grant admin consent for {tenant}**. All entries should
turn green.

### 5. Sign-in account requirements

The user who signs in via device code must be one of:

- **Global Administrator**, **Power Platform Administrator**, or
- **Dynamics 365 Administrator** with rights in the target environments.

Without admin rights you'll get `403 InsufficientDelegatedPermissions` from
the PVA endpoint even after consenting the app.

---

## Networking caveats

The Power Platform endpoints (`api.bap.microsoft.com`,
`*.environment.api.powerplatform.com`) trigger TLS renegotiation that some
on-device security agents handle poorly. Symptoms:

- `The underlying connection was closed: An unexpected error occurred on a send.`
- `Received an unexpected EOF or 0 bytes from the transport stream.`
- `curl: (35) schannel: failed to receive handshake, SSL/TLS connection failed`

Common culprits: **Microsoft Entra Global Secure Access / Private Access**,
ZScaler, NetSkope, corporate TLS-inspecting proxies.

The script already retries transport errors with exponential backoff. If it
still fails, try (in order):

1. **Pause the Global Secure Access / proxy client** in the system tray for the
   duration of the run.
2. Have your admin **exclude** these FQDNs from inspection:
   - `*.api.bap.microsoft.com`
   - `*.api.powerplatform.com`
   - `*.environment.api.powerplatform.com`
3. Run from a network without the inspecting proxy (e.g., phone hotspot) to
   confirm.

---

## Output

For each environment the script prints:

```
Environment: <Display Name> (<env id>)
  POST https://<envIdHost>.environment.api.powerplatform.com/powervirtualagents/api/securityExtensibility/test?api-version=2022-03-01-preview
  Success
```

…or, on failure, the full HTTP status, response headers, and response body.

A summary line counts successes / failures / skipped, and the script returns a
`PSCustomObject[]` of per-environment results so you can pipe to
`Export-Csv`, `ConvertTo-Json`, etc.:

```powershell
$results = .\Invoke-PvaSecurityExtensibilityTestAllEnvironments.ps1 `
    -Endpoint "https://your-extensibility-endpoint.example.com" `
    -AppId    "00000000-0000-0000-0000-000000000000" `
    -TenantId "00000000-0000-0000-0000-000000000000" `
    -ClientId "00000000-0000-0000-0000-000000000000"

$results | Export-Csv .\pva-extensibility-test-results.csv -NoTypeInformation
```

---

## License

MIT. See [LICENSE](LICENSE).
